<?php
/**
 * WP Diagnostic AI — index.php
 * Single entry point. Bootstrap + router + SSE + async worker.
 * Credentials travel in every request (no dependency on $_SESSION).
 *
 * v1.0.9 — Scanner API keys (VirusTotal, Sucuri) are user-provided per-run.
 *
 * URL router — actions:
 *   ?action=ping             → server diagnostics
 *   ?action=detect           → detect auxiliary plugin
 *   ?action=verify           → verify WPDiag Key against /context
 *   ?action=install          → install plugin via admin panel automation
 *   ?action=get_key          → retrieve WPDiag Key automatically
 *   ?action=run              → start pipeline (returns run_id)
 *   ?action=run_bg           → background worker (internal use only)
 *   ?action=state            → current pipeline state (SSE fallback)
 *   ?action=stream           → Server-Sent Events
 *   ?action=plugin_zip       → download auxiliary plugin ZIP
 *   ?action=download_plugin  → download auxiliary plugin PHP file
 */

declare(strict_types=1);

if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start();
}

define('ABSPATH', __DIR__);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/gemini.php';
require_once __DIR__ . '/context.php';
require_once __DIR__ . '/forensics.php';
require_once __DIR__ . '/agents.php';
require_once __DIR__ . '/pipeline.php';

// ─── Router ───────────────────────────────────────────────────
$action = $_GET['action'] ?? null;

switch ($action) {

    case 'ping':
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo json_encode(handle_ping(), JSON_UNESCAPED_UNICODE);
        exit;

    case 'stream':
        handle_stream();
        exit;

    case 'run_bg':
        handle_run_bg();
        exit;

    case 'plugin_zip':
        handle_plugin_zip();
        exit;

    case 'download_plugin':
        handle_download_plugin();
        exit;

    case 'detect':
    case 'verify':
    case 'install':
    case 'get_key':
    case 'run':
    case 'state':
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        try {
            $fn = 'handle_' . $action;
            echo json_encode($fn(), JSON_UNESCAPED_UNICODE);
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode([
                'status'  => 'error',
                'message' => 'Internal exception: ' . $e->getMessage(),
            ]);
        }
        exit;
}

// ─── Default view ─────────────────────────────────────────────
require __DIR__ . '/render.php';

// ═══════════════════════════════════════════════════════════════
// REQUEST HELPERS
// ═══════════════════════════════════════════════════════════════

function wpdiag_json_input(): array {
    $raw = file_get_contents('php://input');
    if (!$raw) return [];
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function wpdiag_new_run_id(): string {
    return bin2hex(random_bytes(16));
}

function wpdiag_validate_site(string $site): ?string {
    $site = trim($site);
    if ($site === '')                            return 'Missing site URL.';
    if (!filter_var($site, FILTER_VALIDATE_URL)) return 'Site URL is not valid.';
    return null;
}

function wpdiag_asset_url(string $relative): string {
    $rel  = ltrim($relative, '/');
    $path = __DIR__ . '/' . $rel;
    $ver  = file_exists($path) ? filemtime($path) : WPDIAG_BUILD;
    return htmlspecialchars($rel . '?v=' . $ver);
}

function wpdiag_generate_plugin_zip(): ?string {
    $source  = __DIR__ . '/wp-plugin/wpdiag-endpoint.php';
    $zipPath = sys_get_temp_dir() . '/wpdiag-endpoint-' . WPDIAG_VERSION . '.zip';

    if (!is_readable($source)) return null;
    if (!class_exists('ZipArchive')) return null;

    $regenerate = !file_exists($zipPath) || (filemtime($source) > filemtime($zipPath));

    if ($regenerate) {
        @unlink($zipPath);
        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            return null;
        }
        $zip->addFile($source, 'wpdiag-endpoint/wpdiag-endpoint.php');
        $zip->close();
    }

    return file_exists($zipPath) ? $zipPath : null;
}

function wpdiag_test_gemini_reachability(): array {
    $ch = curl_init('https://generativelanguage.googleapis.com/');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_NOBODY         => true,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    curl_exec($ch);
    $err   = curl_error($ch);
    $errno = curl_errno($ch);
    $info  = curl_getinfo($ch);
    curl_close($ch);

    return [
        'reachable'  => $err === '',
        'curl_errno' => $errno,
        'curl_error' => $err,
        'dns_ms'     => round(($info['namelookup_time'] ?? 0) * 1000),
        'connect_ms' => round(($info['connect_time']   ?? 0) * 1000),
        'total_ms'   => round(($info['total_time']     ?? 0) * 1000),
    ];
}

// ═══════════════════════════════════════════════════════════════
// HANDLERS
// ═══════════════════════════════════════════════════════════════

function handle_ping(): array {
    return [
        'status'       => 'ok',
        'app'          => WPDIAG_NAME,
        'version'      => WPDIAG_VERSION,
        'build'        => WPDIAG_BUILD,
        'php'          => PHP_VERSION,
        'zip_support'  => class_exists('ZipArchive'),
        'curl_support' => function_exists('curl_init'),
        'gemini_test'  => wpdiag_test_gemini_reachability(),
        'handlers' => [
            'detect', 'verify', 'install', 'get_key', 'run', 'run_bg',
            'state', 'stream', 'plugin_zip', 'download_plugin', 'ping',
        ],
    ];
}

/**
 * STEP 1: site URL + Gemini key → detect auxiliary plugin.
 * Does NOT require the WPDiag Key yet.
 */
function handle_detect(): array {
    $in = wpdiag_json_input();

    $site       = trim((string)($in['site_url']   ?? ''));
    $gemini_key = trim((string)($in['gemini_key'] ?? ''));

    if (($err = wpdiag_validate_site($site)) !== null) {
        return ['status' => 'error', 'message' => $err];
    }
    if ($gemini_key === '') {
        return ['status' => 'error', 'message' => 'Missing Gemini API Key.'];
    }

    $site = rtrim($site, '/');
    $r    = detect_plugin($site);

    if (!$r['ok']) {
        return ['status' => 'error', 'message' => $r['message']];
    }

    if ($r['installed']) {
        return ['status' => 'installed', 'version' => $r['version']];
    }

    return ['status' => 'not_installed'];
}

/**
 * STEP 2A: plugin already installed → validate WPDiag Key against /context.
 */
function handle_verify(): array {
    $in = wpdiag_json_input();

    $site       = trim((string)($in['site_url']   ?? ''));
    $gemini_key = trim((string)($in['gemini_key'] ?? ''));
    $wpdiag_key = trim((string)($in['wpdiag_key'] ?? ''));

    if (($err = wpdiag_validate_site($site)) !== null) {
        return ['status' => 'error', 'message' => $err];
    }
    if ($gemini_key === '') {
        return ['status' => 'error', 'message' => 'Missing Gemini API Key.'];
    }
    if ($wpdiag_key === '') {
        return ['status' => 'error', 'message' => 'Missing WPDiag Key.'];
    }

    $site = rtrim($site, '/');
    $v    = verify_plugin($site, $wpdiag_key);

    if ($v['ok'] ?? false) return ['status' => 'ok'];

    if (($v['type'] ?? '') === 'auth') {
        return ['status' => 'error', 'message' => WPDIAG_ERRORS['plugin_invalid_key']];
    }

    return ['status' => 'error', 'message' => $v['message'] ?? 'Could not validate the key.'];
}

/**
 * STEP 2B: plugin not installed → install via admin panel automation.
 */
function handle_install(): array {
    $in = wpdiag_json_input();

    $site       = trim((string)($in['site_url']   ?? ''));
    $gemini_key = trim((string)($in['gemini_key'] ?? ''));
    $wp_user    = trim((string)($in['wp_user']    ?? ''));
    $wp_pass    = (string)($in['wp_password'] ?? '');

    if (($err = wpdiag_validate_site($site)) !== null) {
        return ['status' => 'error', 'message' => $err];
    }
    if ($gemini_key === '') {
        return ['status' => 'error', 'message' => 'Missing Gemini API Key.'];
    }
    if ($wp_user === '' || $wp_pass === '') {
        return ['status' => 'error', 'message' => 'WordPress username and password are required.'];
    }

    if (!class_exists('ZipArchive')) {
        return ['status' => 'error', 'message' => 'The server does not have the ZipArchive extension enabled.'];
    }

    $site = rtrim($site, '/');
    $zip_path = wpdiag_generate_plugin_zip();
    if (!$zip_path) {
        return ['status' => 'error', 'message' => 'Could not generate the plugin ZIP.'];
    }

    $r = install_plugin_via_admin($site, $wp_user, $wp_pass, $zip_path);
    unset($wp_pass, $in['wp_password']);

    if ($r['ok'] ?? false) {
        return [
            'status'     => 'ok',
            'wpdiag_key' => $r['api_key'],
            'message'    => $r['message'] ?? '',
        ];
    }

    return [
        'status'  => 'error',
        'message' => $r['message'] ?? 'Error installing the plugin.',
        'type'    => $r['type']    ?? 'unknown',
        'debug'   => $r['debug']   ?? null,
    ];
}

/**
 * STEP 3: plugin already active → retrieve WPDiag Key automatically.
 */
function handle_get_key(): array {
    $in = wpdiag_json_input();

    $site       = trim((string)($in['site_url']   ?? ''));
    $gemini_key = trim((string)($in['gemini_key'] ?? ''));
    $wp_user    = trim((string)($in['wp_user']    ?? ''));
    $wp_pass    = (string)($in['wp_password'] ?? '');

    if (($err = wpdiag_validate_site($site)) !== null) {
        return ['status' => 'error', 'message' => $err];
    }
    if ($gemini_key === '') {
        return ['status' => 'error', 'message' => 'Missing Gemini API Key.'];
    }
    if ($wp_user === '' || $wp_pass === '') {
        return ['status' => 'error', 'message' => 'WordPress username and password are required.'];
    }

    $site = rtrim($site, '/');

    $login = wp_login($site, $wp_user, $wp_pass);
    if (!$login['ok']) {
        unset($wp_pass, $in['wp_password']);
        return [
            'status'  => 'error',
            'message' => $login['message'] ?? 'Could not log in.',
            'type'    => $login['type']    ?? 'login',
        ];
    }

    $key = get_setup_key_with_cookies($site, $login['cookies']);
    unset($wp_pass, $in['wp_password']);

    if (empty($key['ok']) || empty($key['api_key'])) {
        return [
            'status'  => 'error',
            'message' => 'Could not read the WPDiag Key automatically. Go to Settings › WP Diagnostics on the site and copy it manually.',
            'type'    => 'key_not_obtained',
        ];
    }

    return ['status' => 'ok', 'wpdiag_key' => $key['api_key']];
}

/**
 * STEP 4: start pipeline.
 *
 * Scanner API keys (VirusTotal, Sucuri) are optional. They travel from
 * the user's browser to the background worker without server-side storage.
 */
function handle_run(): array {
    $in = wpdiag_json_input();

    $site       = trim((string)($in['site_url']        ?? ''));
    $gemini_key = trim((string)($in['gemini_key']      ?? ''));
    $wpdiag_key = trim((string)($in['wpdiag_key']      ?? ''));
    $vt_key     = trim((string)($in['vt_api_key']      ?? ''));
    $sucuri_key = trim((string)($in['sucuri_api_key']  ?? ''));

    if (($err = wpdiag_validate_site($site)) !== null) {
        return ['status' => 'error', 'message' => $err];
    }
    if ($gemini_key === '') {
        return ['status' => 'error', 'message' => 'Missing Gemini API Key.'];
    }
    if ($wpdiag_key === '') {
        return ['status' => 'error', 'message' => 'Missing WPDiag Key.'];
    }

    $site   = rtrim($site, '/');
    $run_id = wpdiag_new_run_id();

    $state = initial_state($site, $run_id);
    _write_progress($state);

    wpdiag_dispatch_worker($run_id, $site, $wpdiag_key, $gemini_key, $vt_key, $sucuri_key);

    return ['status' => 'ok', 'run_id' => $run_id];
}

/**
 * Background worker. Called internally by wpdiag_dispatch_worker().
 */
function handle_run_bg(): void {
    ignore_user_abort(true);
    @set_time_limit(300);

    $in = wpdiag_json_input();

    $run_id     = (string)($in['run_id']          ?? '');
    $site       = trim((string)($in['site_url']      ?? ''));
    $wpdiag     = trim((string)($in['wpdiag_key']    ?? ''));
    $gemini     = trim((string)($in['gemini_key']    ?? ''));
    $vt_key     = trim((string)($in['vt_api_key']     ?? ''));
    $sucuri_key = trim((string)($in['sucuri_api_key'] ?? ''));

    if ($run_id === '') {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'run_bg requires run_id']);
        return;
    }

    if ($site === '' || $wpdiag === '' || $gemini === '') {
        wpdiag_worker_error($run_id, 'Missing credentials in worker.');
        return;
    }

    try {
        run_pipeline($site, $wpdiag, $gemini, $run_id, $vt_key, $sucuri_key);
    } catch (Throwable $e) {
        wpdiag_worker_error($run_id, 'Exception in worker: ' . $e->getMessage());
    }
}

/**
 * Current pipeline state (SSE fallback).
 */
function handle_state(): array {
    $run_id = (string)($_GET['run_id'] ?? '');
    if ($run_id === '') {
        return ['current_step' => 0, 'completed' => false];
    }
    $data = read_progress($run_id);
    if ($data === null) {
        return ['current_step' => 0, 'completed' => false];
    }
    return $data;
}

/**
 * Server-Sent Events. Emits `state` each time the temp file changes.
 */
function handle_stream(): void {
    header('Content-Type: text/event-stream; charset=utf-8');
    header('Cache-Control: no-cache, no-transform');
    header('Connection: keep-alive');
    header('X-Accel-Buffering: no');

    while (ob_get_level() > 0) { ob_end_flush(); }
    ob_implicit_flush(true);

    ignore_user_abort(false);

    $run_id = (string)($_GET['run_id'] ?? '');

    echo "retry: 60000\n";
    echo ": wpdiag stream open\n\n";
    flush();

    if ($run_id === '') {
        echo "event: fatal\n";
        echo 'data: ' . json_encode([
            'type'    => 'missing_run_id',
            'message' => 'Stream did not receive run_id.',
        ], JSON_UNESCAPED_UNICODE) . "\n\n";
        flush();
        return;
    }

    $last_hash = null;
    $deadline  = time() + 300;
    $idle      = 0;
    $max_idle  = 30;

    while (time() < $deadline) {

        if (connection_aborted()) return;

        $data = read_progress($run_id);

        if ($data === null) {
            $idle++;
            if ($idle > $max_idle) {
                echo "event: fatal\n";
                echo 'data: ' . json_encode([
                    'type'    => 'no_state',
                    'message' => 'Pipeline has not produced state in 15 seconds.',
                ], JSON_UNESCAPED_UNICODE) . "\n\n";
                flush();
                return;
            }
            echo ": ping\n\n";
            flush();
            usleep(500_000);
            continue;
        }

        $hash = $data['_hash'] ?? md5(json_encode($data));

        if ($hash !== $last_hash) {
            $last_hash = $hash;
            $idle      = 0;

            echo "event: state\n";
            echo 'data: ' . json_encode($data, JSON_UNESCAPED_UNICODE) . "\n\n";
            flush();
        } else {
            echo ": ping\n\n";
            flush();
        }

        if (!empty($data['completed'])) {
            echo "event: done\n";
            echo 'data: ' . json_encode(['ok' => true], JSON_UNESCAPED_UNICODE) . "\n\n";
            flush();
            return;
        }

        usleep(500_000);
    }

    echo "event: fatal\n";
    echo 'data: ' . json_encode([
        'type'    => 'stream_timeout',
        'message' => 'Stream exceeded 5 minutes without closing.',
    ], JSON_UNESCAPED_UNICODE) . "\n\n";
    flush();
}

function handle_plugin_zip(): void {
    $zipPath = wpdiag_generate_plugin_zip();
    if (!$zipPath) {
        http_response_code(500);
        echo 'Could not generate the plugin ZIP.';
        return;
    }

    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="wpdiag-endpoint.zip"');
    header('Content-Length: ' . filesize($zipPath));
    header('Cache-Control: no-store');
    readfile($zipPath);
}

function handle_download_plugin(): void {
    $path = __DIR__ . '/wp-plugin/wpdiag-endpoint.php';
    if (!is_readable($path)) {
        http_response_code(404);
        echo 'Plugin not available.';
        return;
    }
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="wpdiag-endpoint.php"');
    header('Content-Length: ' . filesize($path));
    header('Cache-Control: no-store');
    readfile($path);
}

// ═══════════════════════════════════════════════════════════════
// INFRASTRUCTURE
// ═══════════════════════════════════════════════════════════════

/**
 * Fire-and-forget dispatch to the background worker.
 * Scanner API keys travel with the body (never persisted server-side).
 */
function wpdiag_dispatch_worker(
    string $run_id,
    string $site,
    string $wpdiag,
    string $gemini,
    string $vt_key     = '',
    string $sucuri_key = ''
): void {
    $host   = $_SERVER['HTTP_HOST']   ?? 'localhost';
    $script = $_SERVER['SCRIPT_NAME'] ?? '/index.php';
    $https  = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
           || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

    $url = ($https ? 'https://' : 'http://') . $host . $script . '?action=run_bg';

    $body = json_encode([
        'run_id'         => $run_id,
        'site_url'       => $site,
        'wpdiag_key'     => $wpdiag,
        'gemini_key'     => $gemini,
        'vt_api_key'     => $vt_key,
        'sucuri_api_key' => $sucuri_key,
    ]);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $body,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT_MS     => 500,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
    ]);

    @curl_exec($ch);
    curl_close($ch);
}

function wpdiag_worker_error(string $run_id, string $msg): void {
    if ($run_id === '') return;

    $state = read_progress($run_id) ?: [];
    $state['run_id']      = $run_id;
    $state['completed']   = true;
    $state['fatal_error'] = ['type' => 'worker', 'message' => $msg];
    $state['_hash']       = md5(serialize($state));
    $state['_ts']         = microtime(true);

    @file_put_contents(_temp_path($run_id), json_encode($state, JSON_UNESCAPED_UNICODE));
}