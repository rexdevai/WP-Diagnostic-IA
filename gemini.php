<?php
/**
 * WP Diagnostic AI — gemini.php
 * HTTP client for the Gemini API.
 * Single responsibility: make the request, handle errors, retry.
 * Knows nothing about WordPress or the agents.
 */

if (!defined('ABSPATH')) exit;

/**
 * Calls the Gemini API and returns the response text.
 *
 * @param string $system_prompt  Agent role instructions
 * @param string $user_message   Content to analyze
 * @param string $api_key        User's Gemini API key
 * @param int    $attempt        Internal retry counter (do not pass manually)
 *
 * @return array {
 *   'ok'      => bool,
 *   'text'    => string|null,   // AI response if ok=true
 *   'error'   => array|null,    // error object if ok=false
 *   'tokens'  => int            // estimated tokens used
 * }
 */
function gemini_request(string $system_prompt, string $user_message, string $api_key, int $attempt = 1): array {

    $url = GEMINI_ENDPOINT . GEMINI_MODEL . GEMINI_ACTION . '?key=' . urlencode($api_key);

    $body = json_encode([
        'system_instruction' => [
            'parts' => [['text' => $system_prompt]]
        ],
        'contents' => [
            [
                'parts' => [['text' => $user_message]]
            ]
        ],
        'generationConfig' => [
            'temperature'     => GEMINI_TEMPERATURE,
            'maxOutputTokens' => GEMINI_MAX_TOKENS,
        ]
    ]);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $body,
        CURLOPT_TIMEOUT        => GEMINI_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);

    $raw        = curl_exec($ch);
    $http       = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_err   = curl_error($ch);
    $curl_errno = curl_errno($ch);
    curl_close($ch);

    // ── Network error (no HTTP response) ─────────────────────
    if ($raw === false || $curl_err) {
        $detail = $curl_err ?: 'No response from server';
        if ($curl_errno) {
            $detail .= ' (cURL errno ' . $curl_errno . ')';
        }
        return _gemini_error(
            'network', 0, $detail, true,
            $system_prompt, $user_message, $api_key, $attempt
        );
    }

    $data = json_decode($raw, true);

    switch (true) {

        case $http === 401 || $http === 403:
            return _gemini_build_error('auth', $http, WPDIAG_ERRORS['auth'], false);

        case $http === 429:
            return _gemini_error('rate_limit', $http, WPDIAG_ERRORS['rate_limit'], true, $system_prompt, $user_message, $api_key, $attempt);

        case $http === 200:
            $text = $data['candidates'][0]['content']['parts'][0]['text'] ?? null;

            if ($text === null) {
                $reason = $data['candidates'][0]['finishReason'] ?? 'UNKNOWN';
                return _gemini_build_error('malformed', 200, "Empty response. Reason: $reason", true);
            }

            $estimated_tokens = _estimate_tokens($system_prompt . $user_message . $text);

            return [
                'ok'     => true,
                'text'   => trim($text),
                'error'  => null,
                'tokens' => $estimated_tokens,
            ];

        case $http >= 500:
            $msg = $data['error']['message'] ?? "Gemini server error (HTTP $http)";
            return _gemini_error('network', $http, $msg, true, $system_prompt, $user_message, $api_key, $attempt);

        default:
            $msg = $data['error']['message'] ?? "Unexpected HTTP: $http";

            if (stripos($msg, 'quota') !== false) {
                return _gemini_build_error('quota', $http, WPDIAG_ERRORS['quota'], false);
            }

            return _gemini_build_error('network', $http, $msg, false);
    }
}

/**
 * Handles retry with exponential backoff.
 * If attempts are exhausted, returns the final error.
 */
function _gemini_error(string $type, int $http, string $msg, bool $retryable, string $system, string $user, string $key, int $attempt): array {

    if (!$retryable || $attempt >= GEMINI_MAX_RETRIES) {
        return _gemini_build_error($type, $http, $msg, $retryable);
    }

    $wait = GEMINI_BACKOFF_BASE * $attempt;
    sleep($wait);

    return gemini_request($system, $user, $key, $attempt + 1);
}

/**
 * Builds the standardized error object.
 * For network errors, includes the technical detail in the user message
 * so it's visible in the UI.
 */
function _gemini_build_error(string $type, int $http, string $msg, bool $retryable): array {
    $friendly = WPDIAG_ERRORS[$type] ?? $msg;

    // For network errors, include the technical detail
    if ($type === 'network' && $msg !== '' && $msg !== $friendly) {
        $friendly .= ' Detail: ' . $msg;
    }

    return [
        'ok'    => false,
        'text'  => null,
        'error' => [
            'type'          => $type,
            'http_code'     => $http,
            'message'       => $msg,
            'retryable'     => $retryable,
            'user_message'  => $friendly,
        ],
        'tokens' => 0,
    ];
}

function _estimate_tokens(string $text): int {
    return (int) ceil(mb_strlen($text) / CONTEXT_CHARS_PER_TOKEN);
}