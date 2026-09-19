<?php
/**
 * WP Diagnostic AI — forensics.php
 * External scanner integration + forensic context preparation.
 * Does NOT scan the site: that's done by the auxiliary plugin.
 *
 * This file:
 *   1. Calls VirusTotal / Sucuri if the user provided API keys for this run.
 *   2. Prepares the bounded prompt for the Forensic Agent.
 *
 * v1.0.9 — Scanner API keys now come from the user per-run (via POST body).
 *          Structured scanner returns with typed error reasons.
 *          VirusTotal polls until the analysis completes (with timeout).
 */

if (!defined('ABSPATH')) exit;

// ─────────────────────────────────────────────────────────────────
// SCANNER ERROR HELPER
// ─────────────────────────────────────────────────────────────────

/**
 * Builds a structured scanner error result.
 */
function _scanner_error(string $reason, string $message = ''): array {
    return [
        'status'  => 'error',
        'reason'  => $reason,
        'message' => $message,
        'data'    => null,
    ];
}

/**
 * Builds a structured scanner success result.
 */
function _scanner_ok(array $data): array {
    return [
        'status'  => 'ok',
        'reason'  => null,
        'message' => null,
        'data'    => $data,
    ];
}

// ─────────────────────────────────────────────────────────────────
// VIRUSTOTAL
// ─────────────────────────────────────────────────────────────────

/**
 * Scans a URL with VirusTotal.
 *
 * Flow:
 *   1. POST /urls           → returns analysis_id
 *   2. GET /analyses/{id}   → poll until status='completed' (with timeout)
 *
 * The analysis is queued server-side; we must wait for completion.
 * Free tier limits: 4 requests/minute, 500/day, 15.5k/month.
 *
 * @return array {
 *   status:  'ok' | 'error' | 'incomplete',
 *   reason:  null | 'not_configured' | 'invalid_key' | 'rate_limit' | 'timeout'
 *            | 'service_down' | 'parse_error' | 'submission_failed' | 'unknown',
 *   message: string|null,
 *   data:    array|null
 * }
 */
function vt_scan_url(string $url, string $api_key): array {

    if ($api_key === '') {
        return _scanner_error('not_configured');
    }

    // ── Step 1: submit URL for analysis ───────────────────────
    $ch = curl_init(WPDIAG_VT_ENDPOINT . '/urls');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_TIMEOUT        => 20,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_HTTPHEADER     => [
            'x-apikey: ' . $api_key,
            'Content-Type: application/x-www-form-urlencoded',
        ],
        CURLOPT_POSTFIELDS     => 'url=' . urlencode($url),
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $raw  = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    $errno = curl_errno($ch);
    curl_close($ch);

    if ($err || $raw === false) {
        if ($errno === CURLE_OPERATION_TIMEDOUT) {
            return _scanner_error('timeout', 'VirusTotal submission timed out.');
        }
        return _scanner_error('unknown', 'VirusTotal submission failed: ' . $err);
    }

    if ($http === 401 || $http === 403) {
        return _scanner_error('invalid_key', 'VirusTotal rejected the API key (HTTP ' . $http . ').');
    }
    if ($http === 429) {
        return _scanner_error('rate_limit', 'VirusTotal rate limit reached (HTTP 429). Free tier: 4 requests/min.');
    }
    if ($http >= 500) {
        return _scanner_error('service_down', 'VirusTotal service error (HTTP ' . $http . ').');
    }
    if ($http !== 200) {
        return _scanner_error('unknown', 'Unexpected HTTP ' . $http . ' from VirusTotal.');
    }

    $body = json_decode($raw, true);
    if (!is_array($body) || empty($body['data']['id'])) {
        return _scanner_error('parse_error', 'Could not extract analysis ID from VirusTotal response.');
    }

    $analysis_id = (string) $body['data']['id'];

    // ── Step 2: poll until analysis completes ─────────────────
    $started = microtime(true);

    while (true) {
        if ((microtime(true) - $started) > WPDIAG_VT_POLL_MAX_WAIT) {
            return _scanner_error('incomplete', 'VirusTotal analysis did not complete within ' . WPDIAG_VT_POLL_MAX_WAIT . ' seconds.');
        }

        sleep(WPDIAG_VT_POLL_INTERVAL);

        $ch = curl_init(WPDIAG_VT_ENDPOINT . '/analyses/' . urlencode($analysis_id));
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_HTTPHEADER     => ['x-apikey: ' . $api_key],
            CURLOPT_SSL_VERIFYPEER => true,
        ]);
        $poll_raw  = curl_exec($ch);
        $poll_http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $poll_err  = curl_error($ch);
        curl_close($ch);

        if ($poll_err || $poll_raw === false) {
            return _scanner_error('timeout', 'VirusTotal poll timed out.');
        }
        if ($poll_http === 429) {
            return _scanner_error('rate_limit', 'VirusTotal rate limit reached during polling.');
        }
        if ($poll_http >= 500) {
            return _scanner_error('service_down', 'VirusTotal service error during polling.');
        }
        if ($poll_http !== 200) {
            return _scanner_error('unknown', 'Unexpected HTTP ' . $poll_http . ' during polling.');
        }

        $poll = json_decode($poll_raw, true);
        $status = $poll['data']['attributes']['status'] ?? null;

        if ($status === 'completed') {
            $stats = $poll['data']['attributes']['stats'] ?? [];
            $malicious  = (int) ($stats['malicious']  ?? 0);
            $suspicious = (int) ($stats['suspicious'] ?? 0);
            $harmless   = (int) ($stats['harmless']   ?? 0);
            $undetected = (int) ($stats['undetected'] ?? 0);

            return _scanner_ok([
                'positives' => $malicious + $suspicious,
                'total'     => $malicious + $suspicious + $harmless + $undetected,
                'stats'     => $stats,
                'details'   => "malicious={$malicious}, suspicious={$suspicious}, harmless={$harmless}, undetected={$undetected}",
            ]);
        }

        if ($status === 'failed') {
            return _scanner_error('unknown', 'VirusTotal analysis failed server-side.');
        }

        // status is 'queued' or 'in_progress' → continue polling
    }
}

// ─────────────────────────────────────────────────────────────────
// SUCURI
// ─────────────────────────────────────────────────────────────────

/**
 * Scans a URL with Sucuri SiteCheck API v3.
 * Requires a paid plan (free tier only covers the web version).
 *
 * @return array  Structured result, same format as vt_scan_url().
 */
function sucuri_scan_url(string $url, string $api_key): array {

    if ($api_key === '') {
        return _scanner_error('not_configured');
    }

    $endpoint = WPDIAG_SUCURI_ENDPOINT . '?scan=' . urlencode($url) . '&key=' . urlencode($api_key);

    $ch = curl_init($endpoint);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 25,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_USERAGENT      => WPDIAG_UA,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $raw   = curl_exec($ch);
    $http  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err   = curl_error($ch);
    $errno = curl_errno($ch);
    curl_close($ch);

    if ($err || $raw === false) {
        if ($errno === CURLE_OPERATION_TIMEDOUT) {
            return _scanner_error('timeout', 'Sucuri request timed out.');
        }
        return _scanner_error('unknown', 'Sucuri request failed: ' . $err);
    }

    if ($http === 401 || $http === 403) {
        return _scanner_error('invalid_key', 'Sucuri rejected the API key (HTTP ' . $http . '). Requires a paid plan.');
    }
    if ($http === 429) {
        return _scanner_error('rate_limit', 'Sucuri rate limit reached (HTTP 429).');
    }
    if ($http >= 500) {
        return _scanner_error('service_down', 'Sucuri service error (HTTP ' . $http . ').');
    }
    if ($http !== 200) {
        return _scanner_error('unknown', 'Unexpected HTTP ' . $http . ' from Sucuri.');
    }

    $body = json_decode($raw, true);
    if (!is_array($body)) {
        return _scanner_error('parse_error', 'Sucuri response is not valid JSON.');
    }

    $malware = !empty($body['MALWARE']) || !empty($body['malware']);

    return _scanner_ok([
        'malware' => $malware,
        'details' => $malware ? 'Sucuri reports malware on the site.' : 'No malware detected by Sucuri.',
        'raw'     => array_slice($body, 0, 5, true),
    ]);
}

// ─────────────────────────────────────────────────────────────────
// SCANNER RESULT FORMATTING
// ─────────────────────────────────────────────────────────────────

/**
 * Formats a scanner result for inclusion in the forensic prompt.
 * Distinguishes OK results from typed errors so the agent can report
 * them clearly to the user.
 */
function _format_scanner_result(string $scanner_name, array $result): string {
    $status = $result['status'] ?? 'unknown';

    // Success case
    if ($status === 'ok' && !empty($result['data'])) {
        $d = $result['data'];

        if ($scanner_name === 'VirusTotal') {
            return "{$d['positives']}/{$d['total']} engines detected threats. {$d['details']}";
        }
        if ($scanner_name === 'Sucuri') {
            return $d['malware'] ? 'MALWARE DETECTED' : 'no malware detected';
        }
        return 'scan completed';
    }

    // Error/incomplete case: map reason to a readable message
    $reason = $result['reason'] ?? 'unknown';

    $messages = [
        'not_configured'    => 'not configured (user did not provide an API key for this run)',
        'invalid_key'       => 'ERROR — invalid API key (' . $reason . '). User should verify the key at the provider.',
        'rate_limit'        => 'ERROR — rate limit reached (429). Retry in 60 seconds.',
        'timeout'           => 'ERROR — request timed out.',
        'service_down'      => 'ERROR — service temporarily unavailable (5xx).',
        'incomplete'        => 'WARNING — analysis did not complete within the timeout window. Result not conclusive.',
        'parse_error'       => 'ERROR — unexpected response format from the provider.',
        'submission_failed' => 'ERROR — could not submit the URL for analysis.',
        'unknown'           => 'ERROR — unknown failure.',
    ];

    return $messages[$reason] ?? 'ERROR — unknown failure.';
}

// ─────────────────────────────────────────────────────────────────
// FORENSIC CONTEXT PREPARATION
// ─────────────────────────────────────────────────────────────────

/**
 * Prepares the forensic context for the agent.
 * Separates explicitly:
 *  · Core integrity (wp-admin, wp-includes, root files)
 *  · Bundled theme integrity (twentytwentyfive, etc.)
 *  · Bundled plugin integrity (akismet, etc.)
 *  · Active plugin integrity
 *  · Suspicious files with checksum verification
 */
function prepare_forensic_context(array $forensics, array $vt, array $sucuri): string {
    $parts = [];

    // ── Scan stats ────────────────────────────────────────────
    $stats = $forensics['scan_stats'] ?? [];
    if (!empty($stats)) {
        $parts[] = "## SCAN STATISTICS\n"
            . "- Files scanned: {$stats['files_scanned']}\n"
            . "- With patterns detected: {$stats['with_patterns']}\n"
            . "- Discarded by valid checksum (legitimate): {$stats['discarded_by_checksum']}\n"
            . "- Discarded by rule (weak pattern without confirmation): {$stats['discarded_by_rule']}\n"
            . "- Discarded as vendored dependency (vendor/, node_modules/): " . ($stats['discarded_vendor'] ?? 0) . "\n"
            . "- Reported as suspicious: {$stats['reported']}";
    }

    // ── Core integrity ────────────────────────────────────────
    $core = $forensics['core_integrity'] ?? [];
    $mismatches = $core['mismatches'] ?? [];
    $missing    = $core['missing']    ?? [];

    if ($mismatches || $missing) {
        $lines = ["## WORDPRESS CORE INTEGRITY (wp-admin, wp-includes, root files)"];
        if ($mismatches) {
            $lines[] = "- Core files MODIFIED vs official:";
            foreach (array_slice($mismatches, 0, WPDIAG_FORENSICS_MAX) as $m) {
                $lines[] = "  · {$m['file']}";
            }
        }
        if ($missing) {
            $lines[] = "- Missing core files:";
            foreach (array_slice($missing, 0, 10) as $f) $lines[] = "  · $f";
        }
        $parts[] = implode("\n", $lines);
    }

    // ── Bundled theme integrity ───────────────────────────────
    $themes_m = $core['themes_mismatches'] ?? [];
    if ($themes_m) {
        $lines = ["## BUNDLED THEME INTEGRITY (themes that ship with WordPress)"];
        $lines[] = "Note: these are WordPress default themes, not user-installed themes. Mismatch indicates modification vs official theme version.";
        foreach (array_slice($themes_m, 0, WPDIAG_FORENSICS_MAX) as $m) {
            $lines[] = "- {$m['theme']} v{$m['version']}: {$m['file']}";
        }
        $parts[] = implode("\n", $lines);
    }

    // ── Bundled plugin integrity ──────────────────────────────
    $plugins_b = $core['plugins_mismatches'] ?? [];
    if ($plugins_b) {
        $lines = ["## BUNDLED PLUGIN INTEGRITY (plugins that ship with WordPress)"];
        $lines[] = "Note: these are WordPress default plugins (e.g. akismet), not user-installed plugins.";
        foreach (array_slice($plugins_b, 0, WPDIAG_FORENSICS_MAX) as $m) {
            $lines[] = "- {$m['plugin']} v{$m['version']}: {$m['file']}";
        }
        $parts[] = implode("\n", $lines);
    }

    // ── Active plugin integrity ───────────────────────────────
    $plugins = $forensics['plugin_integrity'] ?? [];
    if (!empty($plugins['mismatches'])) {
        $lines = ["## ACTIVE PLUGIN INTEGRITY (checksums vs wp.org)"];
        foreach (array_slice($plugins['mismatches'], 0, WPDIAG_FORENSICS_MAX) as $m) {
            $lines[] = "- {$m['plugin']} v{$m['version']}: {$m['file']} — {$m['reason']}";
        }
        $parts[] = implode("\n", $lines);
    }

    // ── Suspicious files ──────────────────────────────────────
    $susp = $forensics['suspicious_files'] ?? [];
    if ($susp) {
        $lines = ["## SUSPICIOUS FILES (verified with origin distinction)"];
        $lines[] = "";
        $lines[] = "VERIFICATION CLASSIFICATION:";
        $lines[] = "· checksum_mismatch → file does NOT match wp.org → STRONG, can be high/critical";
        $lines[] = "· extra_file → not listed in wp.org → STRONG";
        $lines[] = "· unverifiable_zone → PHP in uploads/ or mu-plugins/ → STRONG";
        $lines[] = "· premium_unverifiable → premium or custom plugin/theme, not on wp.org → NOT SUSPICIOUS. Only mention as informational.";
        $lines[] = "· wporg_unverifiable → on wp.org but no checksums or ZIP available → WEAK, max medium severity";
        $lines[] = "· no_checksum_legit_name → very weak, almost certainly false positive";
        $lines[] = "";
        $lines[] = "ORIGIN CLASSIFICATION:";
        $lines[] = "· core → WordPress core file";
        $lines[] = "· wporg_verified → theme/plugin on wp.org with checksums obtained";
        $lines[] = "· wporg_unverified → theme/plugin on wp.org but checksums unavailable";
        $lines[] = "· premium_or_custom → theme/plugin NOT on wp.org (premium or custom)";
        $lines[] = "· custom_mu_plugin → custom mu-plugin";
        $lines[] = "· suspicious_zone → file in uploads/";
        $lines[] = "";
        foreach (array_slice($susp, 0, WPDIAG_FORENSICS_MAX) as $s) {
            $verif  = $s['verification'] ?? 'no_checksum';
            $loc    = $s['location']     ?? '';
            $origin = $s['origin']       ?? 'unknown';
            $lines[] = "- {$s['path']}";
            $lines[] = "  · Pattern: {$s['reason']}";
            $lines[] = "  · Location: {$loc}";
            $lines[] = "  · Verification: {$verif}";
            $lines[] = "  · Origin: {$origin}";
            $lines[] = "  · Severity: {$s['severity']}";
        }
        $parts[] = implode("\n", $lines);
    } else {
        $parts[] = "## SUSPICIOUS FILES\n- No suspicious files detected after checksum verification.";
    }

    // ── Recent changes ────────────────────────────────────────
    $recent = $forensics['recent_changes'] ?? [];
    if ($recent) {
        $lines = ["## FILES MODIFIED IN THE LAST " . WPDIAG_FORENSICS_DAYS . " DAYS"];
        $lines[] = "IMPORTANT: this is just an mtime record. NOT evidence of compromise. Recently installed plugins and updated themes appear here.";
        foreach (array_slice($recent, 0, WPDIAG_FORENSICS_MAX) as $r) {
            $lines[] = "- {$r['path']} (mod: {$r['mtime']}, size: {$r['size']} bytes)";
        }
        $parts[] = implode("\n", $lines);
    }

    // ── .htaccess ─────────────────────────────────────────────
    if (!empty($forensics['htaccess_suspicious'])) {
        $parts[] = "## SUSPICIOUS .HTACCESS\n" .
                    ($forensics['htaccess_excerpt'] ?? 'Suspicious rules detected in .htaccess.');
    }

    // ── Cron ──────────────────────────────────────────────────
    $cron = $forensics['cron_suspicious'] ?? [];
    if ($cron) {
        $lines = ["## SUSPICIOUS CRON TASKS"];
        foreach (array_slice($cron, 0, 10) as $c) $lines[] = "- $c";
        $parts[] = implode("\n", $lines);
    }

    // ── External scanners ─────────────────────────────────────
    // Both VT and Sucuri always return structured results (never null).
    // They format as "OK result", "not configured", or "ERROR — reason".
    $scanner_lines = [];
    $scanner_lines[] = "- VirusTotal: " . _format_scanner_result('VirusTotal', $vt);
    $scanner_lines[] = "- Sucuri: "     . _format_scanner_result('Sucuri',     $sucuri);
    $parts[] = "## EXTERNAL SCANNER\n" . implode("\n", $scanner_lines);

    return implode("\n\n", $parts);
}