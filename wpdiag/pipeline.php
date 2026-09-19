<?php
/**
 * WP Diagnostic AI — pipeline.php
 * Pipeline orchestrator + automatic plugin installation via WordPress
 * admin panel automation + post-Analyzer deterministic findings injection.
 *
 * v1.0.9 — Scanner API keys come from user per-run (via run_pipeline params).
 *          Scanners now return structured arrays (never null).
 *
 * Depends on: config.php, gemini.php, context.php, forensics.php, agents.php
 */

if (!defined('ABSPATH')) exit;

// ─────────────────────────────────────────────────────────────────
// INITIAL STATE
// ─────────────────────────────────────────────────────────────────

function initial_state(string $site_url, string $run_id): array {
    return [
        'run_id'                 => $run_id,
        'site_url'               => rtrim($site_url, '/'),
        'context_raw'            => null,
        'context_prompt'         => '',
        'context_summary'        => null,
        'forensic_context'       => '',
        'forensics_raw'          => null,
        'estimated_tokens'       => 0,
        'forensic_agent'         => null,
        'analyzer'               => null,
        'verifier'               => null,
        'writer'                 => null,
        'operator'               => null,
        'final_diagnosis'        => null,
        'client_response'        => '',
        'actions'                => [],
        'current_step'           => 0,
        'completed'              => false,
        'requires_human'         => false,
        'requires_human_reason'  => '',
        'errors'                 => [],
        'fatal_error'            => null,
        'internal_log'           => [],
        'start_time'             => microtime(true),
        'total_time'             => 0,
        'timestamp'              => date('Y-m-d H:i:s'),
    ];
}

// ─────────────────────────────────────────────────────────────────
// TEMP PROGRESS FILE
// ─────────────────────────────────────────────────────────────────

function _temp_path(string $run_id): string {
    $safe = preg_replace('/[^a-zA-Z0-9_-]/', '', $run_id);
    if ($safe === '') $safe = 'anon';
    return sys_get_temp_dir() . '/' . WPDIAG_SESSION_PREFIX . $safe . '.json';
}

function _write_progress(array $state): void {
    $run_id = (string)($state['run_id'] ?? '');
    if ($run_id === '') return;

    $data = $state;
    $data['_hash'] = md5(serialize($state));
    $data['_ts']   = microtime(true);
    @file_put_contents(_temp_path($run_id), json_encode($data, JSON_UNESCAPED_UNICODE));
}

function read_progress(string $run_id): ?array {
    $path = _temp_path($run_id);
    if (!file_exists($path)) return null;
    $raw  = @file_get_contents($path);
    if ($raw === false || $raw === '') return null;
    $data = json_decode($raw, true);
    return is_array($data) ? $data : null;
}

function clear_progress(string $run_id): void {
    $path = _temp_path($run_id);
    if (file_exists($path)) @unlink($path);
}

// ─────────────────────────────────────────────────────────────────
// PLUGIN DETECTION / VERIFICATION
// ─────────────────────────────────────────────────────────────────

function detect_plugin(string $site_url): array {
    $url = rtrim($site_url, '/') . WPDIAG_STATUS_PATH . '?nocache=' . time();

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT      => WPDIAG_UA,
        CURLOPT_FRESH_CONNECT  => true,
    ]);

    $raw  = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);

    if ($err || $raw === false) {
        return ['ok' => false, 'installed' => false, 'type' => 'network', 'message' => WPDIAG_ERRORS['site_unreachable'] . ' (' . $err . ')'];
    }
    if ($http === 404) {
        return ['ok' => true, 'installed' => false, 'type' => 'not_installed', 'message' => WPDIAG_ERRORS['plugin_not_installed']];
    }
    if ($http !== 200) {
        return ['ok' => false, 'installed' => false, 'type' => 'network', 'message' => "Site responded HTTP $http."];
    }

    $data = json_decode($raw, true);
    if (!is_array($data) || empty($data['ok'])) {
        return ['ok' => false, 'installed' => false, 'type' => 'malformed', 'message' => 'The /status endpoint responded with unexpected data.'];
    }

    return ['ok' => true, 'installed' => true, 'type' => 'installed', 'message' => 'Plugin detected.', 'version' => $data['version'] ?? null];
}

function verify_plugin(string $site_url, string $wpdiag_key): array {
    $url = rtrim($site_url, '/') . WPDIAG_ENDPOINT_PATH . '?nocache=' . time();

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 60,
        CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_HTTPHEADER     => [WPDIAG_KEY_HEADER . ': ' . $wpdiag_key],
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT      => WPDIAG_UA,
        CURLOPT_FRESH_CONNECT  => true,
    ]);

    $raw   = curl_exec($ch);
    $http  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err   = curl_error($ch);
    $errno = curl_errno($ch);
    curl_close($ch);

    if ($err || $raw === false) {
        if ($errno === CURLE_OPERATION_TIMEDOUT) {
            return ['ok' => false, 'type' => 'timeout', 'message' => 'Site took more than 60 seconds to respond to /context.'];
        }
        return ['ok' => false, 'type' => 'network', 'message' => WPDIAG_ERRORS['site_unreachable'] . ' Detail: ' . $err];
    }

    if ($http === 401 || $http === 403) return ['ok' => false, 'type' => 'auth', 'message' => WPDIAG_ERRORS['plugin_invalid_key']];
    if ($http === 404) return ['ok' => false, 'type' => 'not_installed', 'message' => WPDIAG_ERRORS['plugin_not_installed']];

    if ($http === 200) {
        $data = json_decode($raw, true);
        if (isset($data['site'])) return ['ok' => true, 'data' => $data];
        return ['ok' => false, 'type' => 'malformed', 'message' => 'The endpoint responded with unexpected data.'];
    }

    $snippet = is_string($raw) ? substr(strip_tags($raw), 0, 200) : '';
    return ['ok' => false, 'type' => 'network', 'message' => "Site responded HTTP $http." . ($snippet ? " Detail: $snippet" : '')];
}

/**
 * Fetches forensic data from the /forensics endpoint.
 * Timeout extended to 300s to tolerate the first ZIP download of
 * themes/plugins without published checksums.
 */
function fetch_forensics(string $site_url, string $wpdiag_key): ?array {
    $url = rtrim($site_url, '/') . WPDIAG_FORENSICS_PATH . '?nocache=' . time();

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 300,
        CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_TCP_KEEPALIVE  => 1,
        CURLOPT_HTTPHEADER     => [WPDIAG_KEY_HEADER . ': ' . $wpdiag_key],
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT      => WPDIAG_UA,
        CURLOPT_FRESH_CONNECT  => true,
    ]);

    $raw  = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);

    if ($err || $http !== 200 || !$raw) return null;

    $data = json_decode($raw, true);
    return is_array($data) ? $data : null;
}

// ─────────────────────────────────────────────────────────────────
// AUTOMATIC INSTALLATION (Path A)
// ─────────────────────────────────────────────────────────────────

function install_plugin_via_admin(string $site_url, string $wp_user, string $wp_pass, string $zip_path): array {
    $site_url = rtrim($site_url, '/');
    $debug    = [];

    $login = wp_login($site_url, $wp_user, $wp_pass);
    $debug['login'] = $login['ok'] ? 'ok' : ($login['type'] ?? 'error');
    if (!$login['ok']) {
        return ['ok' => false, 'type' => $login['type'] ?? 'login', 'message' => $login['message'] ?? 'Authentication error.', 'debug' => $debug];
    }

    $cookies = $login['cookies'];

    $upload = upload_plugin_via_admin($site_url, $cookies, $zip_path);
    $debug['upload'] = $upload['ok'] ? 'ok' : ($upload['type'] ?? 'error');
    if (!$upload['ok']) {
        return ['ok' => false, 'type' => $upload['type'] ?? 'upload', 'message' => $upload['message'], 'debug' => $debug];
    }

    $activate = activate_plugin_via_admin($site_url, $cookies, 'wpdiag-endpoint/wpdiag-endpoint.php');
    $debug['activate'] = $activate['ok'] ? 'ok' : ($activate['type'] ?? 'error');
    if (!$activate['ok']) {
        return ['ok' => false, 'type' => 'activation', 'message' => 'Plugin uploaded but could not be activated: ' . ($activate['message'] ?? ''), 'manual' => true, 'debug' => $debug];
    }

    sleep(1);
    $status = detect_plugin($site_url);
    $debug['status'] = (!empty($status['installed'])) ? 'ok' : 'no_response';
    if (!$status['ok'] || empty($status['installed'])) {
        return ['ok' => false, 'type' => 'verification', 'message' => 'Plugin activated but /status does not respond.', 'manual' => true, 'debug' => $debug];
    }

    $key_result = get_setup_key_with_cookies($site_url, $cookies);
    $debug['setup_key'] = $key_result['ok'] ? 'ok' : ($key_result['type'] ?? 'error');
    if (!$key_result['ok'] || empty($key_result['api_key'])) {
        return ['ok' => false, 'type' => 'key_not_obtained', 'message' => 'Plugin active but the WPDiag Key could not be read automatically.', 'manual' => true, 'debug' => $debug];
    }

    return ['ok' => true, 'api_key' => $key_result['api_key'], 'message' => 'Plugin installed, activated, and connected successfully.', 'debug' => $debug];
}

// ─────────────────────────────────────────────────────────────────
// ADMIN PANEL AUTOMATION HELPERS
// ─────────────────────────────────────────────────────────────────

function wp_login(string $site_url, string $user, string $pass): array {
    $site_url = rtrim($site_url, '/');

    $ch = curl_init($site_url . '/wp-login.php');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_TIMEOUT => 20,
        CURLOPT_SSL_VERIFYPEER => true, CURLOPT_USERAGENT => WPDIAG_UA, CURLOPT_FOLLOWLOCATION => false,
    ]);
    $resp = curl_exec($ch);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $err = curl_error($ch);
    curl_close($ch);

    if ($resp === false || $err) return ['ok' => false, 'type' => 'network', 'message' => 'Could not connect to wp-login.php: ' . $err];

    $headers = substr($resp, 0, $header_size);
    $cookies = parse_cookies($headers);

    $post = http_build_query([
        'log' => $user, 'pwd' => $pass, 'wp-submit' => 'Log In',
        'redirect_to' => $site_url . '/wp-admin/', 'testcookie' => '1',
    ]);

    $ch = curl_init($site_url . '/wp-login.php');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $post, CURLOPT_TIMEOUT => 20, CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT => WPDIAG_UA, CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_COOKIE => cookie_header($cookies),
    ]);
    $resp = curl_exec($ch);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);

    if ($resp === false || $err) return ['ok' => false, 'type' => 'network', 'message' => 'Error in login POST: ' . $err];

    $headers_resp = substr($resp, 0, $header_size);
    $body = substr($resp, $header_size);
    $new_cookies = parse_cookies($headers_resp);
    $cookies = array_merge($cookies, $new_cookies);

    $logged_in = false;
    foreach ($cookies as $name => $_) {
        if (strpos($name, 'wordpress_logged_in_') === 0) { $logged_in = true; break; }
    }

    if (!$logged_in) {
        if (stripos($body, 'login_error') !== false
            || stripos($body, 'Unknown username') !== false
            || stripos($body, 'nombre de usuario desconocido') !== false
            || stripos($body, 'contraseña que has introducido') !== false
            || stripos($body, 'password you entered') !== false
        ) {
            return ['ok' => false, 'type' => 'credentials', 'message' => WPDIAG_ERRORS['wp_credentials']];
        }
        if ($http === 302 && preg_match('/^Location:\s*(.+)$/im', $headers_resp, $m)) {
            $loc = trim($m[1]);
            if (stripos($loc, 'wp-login.php') === false && stripos($loc, 'wp-admin') === false) {
                return ['ok' => false, 'type' => '2fa', 'message' => 'Site requires additional authentication (2FA or security plugin).'];
            }
        }
        return ['ok' => false, 'type' => 'login', 'message' => 'Could not log in. The site may have a security plugin blocking automated login.'];
    }

    return ['ok' => true, 'cookies' => $cookies];
}

function upload_plugin_via_admin(string $site_url, array $cookies, string $zip_path): array {
    if (!is_readable($zip_path)) return ['ok' => false, 'type' => 'zip', 'message' => 'ZIP does not exist or is not readable.'];

    $cookie_header = cookie_header($cookies);

    $ch = curl_init($site_url . '/wp-admin/plugin-install.php?tab=upload');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 30, CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT => WPDIAG_UA, CURLOPT_FOLLOWLOCATION => true, CURLOPT_COOKIE => $cookie_header,
    ]);
    $html = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);

    if ($html === false || $err) return ['ok' => false, 'type' => 'network', 'message' => 'Could not access installation panel: ' . $err];
    if ($http !== 200) return ['ok' => false, 'type' => 'admin', 'message' => "plugin-install.php responded HTTP $http."];

    if (!preg_match('/name="_wpnonce"\s+value="([a-zA-Z0-9]+)"/', $html, $m)) {
        return ['ok' => false, 'type' => 'nonce', 'message' => 'Could not extract the panel token.'];
    }
    $nonce = $m[1];

    $ch = curl_init($site_url . '/wp-admin/update.php?action=upload-plugin');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_POST => true, CURLOPT_TIMEOUT => 90,
        CURLOPT_SSL_VERIFYPEER => true, CURLOPT_USERAGENT => WPDIAG_UA, CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_COOKIE => $cookie_header,
        CURLOPT_POSTFIELDS => [
            '_wpnonce' => $nonce,
            '_wp_http_referer' => '/wp-admin/plugin-install.php?tab=upload',
            'pluginzip' => new CURLFile($zip_path, 'application/zip', basename($zip_path)),
            'install-plugin-submit' => 'Install Now',
        ],
    ]);
    $html_resp = curl_exec($ch);
    $http_resp = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err_resp = curl_error($ch);
    curl_close($ch);

    if ($html_resp === false || $err_resp) return ['ok' => false, 'type' => 'network', 'message' => 'Error uploading ZIP: ' . $err_resp];
    if ($http_resp !== 200) return ['ok' => false, 'type' => 'upload', 'message' => "update.php responded HTTP $http_resp."];

    $success = stripos($html_resp, 'Plugin installed successfully') !== false
          || stripos($html_resp, 'Successfully installed') !== false
          || stripos($html_resp, 'instalado correctamente') !== false
          || stripos($html_resp, 'plugin-install.php?tab=upload&success=true') !== false;

    if ($success) return ['ok' => true, 'message' => 'ZIP uploaded and installed.'];
    if (stripos($html_resp, 'Destination folder already exists') !== false) return ['ok' => true, 'message' => 'Plugin was already installed.'];
    if (stripos($html_resp, 'The package could not be installed') !== false) return ['ok' => false, 'type' => 'package', 'message' => 'WordPress rejected the ZIP.'];
    if (stripos($html_resp, 'Unable to connect to the filesystem') !== false || stripos($html_resp, 'No se puede conectar al sistema de archivos') !== false) {
        return ['ok' => false, 'type' => 'filesystem', 'message' => 'WordPress cannot write to /wp-content/plugins/.'];
    }
    if (stripos($html_resp, 'Sorry, you are not allowed to install plugins') !== false) return ['ok' => false, 'type' => 'permissions', 'message' => 'User does not have permission to install plugins.'];

    return ['ok' => false, 'type' => 'unknown', 'message' => 'WordPress returned an unexpected response while uploading the ZIP.'];
}

function activate_plugin_via_admin(string $site_url, array $cookies, string $plugin_file): array {
    $cookie_header = cookie_header($cookies);

    $ch = curl_init($site_url . '/wp-admin/plugins.php');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 30, CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT => WPDIAG_UA, CURLOPT_FOLLOWLOCATION => true, CURLOPT_COOKIE => $cookie_header,
    ]);
    $html = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);

    if ($html === false || $err) return ['ok' => false, 'type' => 'network', 'message' => 'Could not load plugins.php: ' . $err];
    if ($http !== 200) return ['ok' => false, 'type' => 'admin', 'message' => "plugins.php responded HTTP $http."];

    $encoded = urlencode($plugin_file);
    $encoded_alt = str_replace('%2F', '/', $encoded);
    $patterns = [
        '/href="[^"]*action=activate[^"]*plugin=' . preg_quote($encoded, '/') . '[^"]*"/i',
        '/href="[^"]*action=activate[^"]*plugin=' . preg_quote($encoded_alt, '/') . '[^"]*"/i',
    ];

    $activation_href = null;
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $html, $m)) {
            if (preg_match('/href="([^"]+)"/', $m[0], $url_m)) {
                $activation_href = html_entity_decode($url_m[1], ENT_QUOTES);
                $activation_href = str_replace('&amp;', '&', $activation_href);
                break;
            }
        }
    }

    if ($activation_href === null) {
        if (preg_match('/action=deactivate[^"]*plugin=' . preg_quote($encoded, '/') . '/i', $html)
            || preg_match('/action=deactivate[^"]*plugin=' . preg_quote($encoded_alt, '/') . '/i', $html)
        ) return ['ok' => true, 'message' => 'Plugin was already active.'];
        if (stripos($html, $plugin_file) === false) return ['ok' => false, 'type' => 'not_found', 'message' => 'Plugin does not appear in the list.'];
        return ['ok' => false, 'type' => 'no_link', 'message' => 'Activation link not found.'];
    }

    if (strpos($activation_href, 'http') !== 0) {
        $activation_href = (strpos($activation_href, 'plugins.php') === 0)
            ? $site_url . '/wp-admin/' . $activation_href
            : $site_url . '/wp-admin/' . ltrim($activation_href, '/');
    }

    $ch = curl_init($activation_href);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 30, CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT => WPDIAG_UA, CURLOPT_FOLLOWLOCATION => true, CURLOPT_COOKIE => $cookie_header,
    ]);
    $html_act = curl_exec($ch);
    $http_act = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err_act = curl_error($ch);
    curl_close($ch);

    if ($html_act === false || $err_act) return ['ok' => false, 'type' => 'network', 'message' => 'Error executing activation: ' . $err_act];
    if ($http_act !== 200) return ['ok' => false, 'type' => 'activation', 'message' => "Activation responded HTTP $http_act."];

    if (stripos($html_act, 'Plugin activated') !== false
        || stripos($html_act, 'Plugin activado') !== false
        || stripos($html_act, 'activate=true') !== false
    ) return ['ok' => true, 'message' => 'Plugin activated.'];

    return ['ok' => true, 'message' => 'Activation executed (subsequent verification).'];
}

function get_setup_key_with_cookies(string $site_url, array $cookies): array {
    $cookie_header = cookie_header($cookies);

    $ch = curl_init($site_url . '/wp-admin/');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20, CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT => WPDIAG_UA, CURLOPT_FOLLOWLOCATION => true, CURLOPT_COOKIE => $cookie_header,
    ]);
    $html = curl_exec($ch);
    curl_close($ch);

    if (!$html) return ['ok' => false, 'type' => 'admin_no_load'];

    $rest_nonce = null;
    if (preg_match('/wpApiSettings\s*=\s*\{[^}]*"nonce"\s*:\s*"([a-zA-Z0-9]+)"/', $html, $m)) $rest_nonce = $m[1];
    elseif (preg_match('/"nonce"\s*:\s*"([a-zA-Z0-9]+)"/', $html, $m)) $rest_nonce = $m[1];

    $ch = curl_init($site_url . '/wp-json/wpdiag/v1/setup-key');
    $headers = [];
    if ($rest_nonce) $headers[] = 'X-WP-Nonce: ' . $rest_nonce;
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 15, CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT => WPDIAG_UA, CURLOPT_COOKIE => $cookie_header, CURLOPT_HTTPHEADER => $headers,
    ]);
    $raw = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http === 200 && $raw) {
        $data = json_decode($raw, true);
        if (!empty($data['api_key'])) return ['ok' => true, 'api_key' => $data['api_key']];
    }

    return scrape_setup_key($site_url, $cookies);
}

function scrape_setup_key(string $site_url, array $cookies): array {
    $ch = curl_init($site_url . '/wp-admin/options-general.php?page=wpdiag-endpoint');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20, CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT => WPDIAG_UA, CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_COOKIE => cookie_header($cookies),
    ]);
    $html = curl_exec($ch);
    curl_close($ch);

    if (!$html) return ['ok' => false, 'type' => 'scrape_no_load'];
    if (preg_match('/<input[^>]*value="([a-zA-Z0-9]{32})"[^>]*readonly/i', $html, $m)) return ['ok' => true, 'api_key' => $m[1]];
    if (preg_match('/<input[^>]*type="text"[^>]*value="([a-zA-Z0-9]{32})"/i', $html, $m)) return ['ok' => true, 'api_key' => $m[1]];
    return ['ok' => false, 'type' => 'scrape_not_found'];
}

function parse_cookies(string $headers): array {
    $cookies = [];
    if (preg_match_all('/^Set-Cookie:\s*([^=]+)=([^;]*)/im', $headers, $matches, PREG_SET_ORDER)) {
        foreach ($matches as $m) $cookies[trim($m[1])] = trim($m[2]);
    }
    return $cookies;
}

function cookie_header(array $cookies): string {
    $parts = [];
    foreach ($cookies as $name => $value) $parts[] = $name . '=' . $value;
    return implode('; ', $parts);
}

// ─────────────────────────────────────────────────────────────────
// DETERMINISTIC FINDINGS INJECTION
// ─────────────────────────────────────────────────────────────────

/**
 * Injects deterministic findings based on context flags.
 * The LLM is not reliable for ALWAYS remembering the same checks,
 * so we guarantee them from code.
 *
 * Broad duplicate detection: searches in type + description + evidence,
 * not only in type. The LLM can name findings in many ways
 * ("configuracion_insegura" for WP_DEBUG, etc.).
 *
 * @param array $diagnosis   Analyzer JSON (by reference)
 * @param array $context_raw Raw plugin data
 * @return array List of injected findings (for log)
 */
function _inject_deterministic_findings(array &$diagnosis, array $context_raw): array {
    $injected = [];

    $findings = $diagnosis['findings'] ?? [];

    $has = function(string ...$needles) use ($findings): bool {
        foreach ($findings as $f) {
            $text = strtolower(
                ($f['type']        ?? '') . ' ' .
                ($f['description'] ?? '') . ' ' .
                ($f['evidence']    ?? '')
            );
            foreach ($needles as $needle) {
                if (strpos($text, strtolower($needle)) !== false) return true;
            }
        }
        return false;
    };

    // ── WP_DEBUG active ───────────────────────────────────────
    if (!empty($context_raw['wordpress']['debug_active']) && !$has('debug', 'wp_debug')) {
        $findings[] = [
            'type'        => 'wp_debug_active',
            'description' => 'WP_DEBUG is active in a production environment.',
            'evidence'    => 'WP_DEBUG active: YES',
            'impact'      => 'Exposes internal paths, errors, and server logic to anyone who triggers an error.',
        ];
        $injected[] = 'wp_debug_active';
    }

    // ── WP_CRON disabled ──────────────────────────────────────
    if (!empty($context_raw['wordpress']['wp_cron_disabled']) && !$has('cron', 'wp_cron')) {
        $findings[] = [
            'type'        => 'wp_cron_disabled',
            'description' => 'WP_CRON is disabled, preventing automatic execution of scheduled tasks.',
            'evidence'    => 'WP_CRON disabled: Yes',
            'impact'      => 'Scheduled posts, updates, and maintenance tasks do not run (unless a system cron is configured).',
        ];
        $injected[] = 'wp_cron_disabled';
    }

    // ── SSL missing ───────────────────────────────────────────
    if (empty($context_raw['wordpress']['ssl_active']) && !$has('ssl', 'https', 'certificate')) {
        $findings[] = [
            'type'        => 'ssl_missing',
            'description' => 'The site does not have active SSL.',
            'evidence'    => 'SSL active: No',
            'impact'      => 'Traffic in plain text, interception risk, and SEO penalty.',
        ];
        $injected[] = 'ssl_missing';
    }

    // ── Missing PHP extensions ────────────────────────────────
    $relevant_ext = ['imagick', 'zip', 'curl', 'gd', 'mbstring', 'openssl'];
    $present_ext  = $context_raw['server']['php_extensions'] ?? [];
    $present_ext  = array_map('strtolower', (array)$present_ext);
    $missing_ext  = array_values(array_diff($relevant_ext, $present_ext));

    if (!empty($missing_ext) && !$has('imagick', 'extension')) {
        $list = implode(', ', $missing_ext);
        $findings[] = [
            'type'        => 'php_extension_missing',
            'description' => "Relevant PHP extensions are missing on the server: {$list}.",
            'evidence'    => "Relevant PHP extensions MISSING: {$list}",
            'impact'      => 'Some site functions (image processing, compression, etc.) may fail or degrade.',
        ];
        $injected[] = 'php_extension_missing:' . $list;
    }

    // ── siteurl/home mismatch ─────────────────────────────────
    $siteurl = $context_raw['critical_options']['siteurl'] ?? '';
    $home    = $context_raw['critical_options']['home']    ?? '';
    if ($siteurl && $home && $siteurl !== $home && !$has('siteurl', 'mismatch', 'home')) {
        $findings[] = [
            'type'        => 'siteurl_home_mismatch',
            'description' => 'siteurl and home do not match, which can cause redirect loops.',
            'evidence'    => "siteurl: {$siteurl} | home: {$home}",
            'impact'      => 'Infinite redirects, admin panel issues, or broken links.',
        ];
        $injected[] = 'siteurl_home_mismatch';
    }

    // ── WordPress Core outdated ───────────────────────────────
    if (!empty($context_raw['updates']['core_available'])
        && !$has('core', 'outdated', 'update')
    ) {
        $current_version = $context_raw['wordpress']['version'] ?? '?';
        $findings[] = [
            'type'        => 'wp_core_outdated',
            'description' => 'WordPress is outdated. Update to the latest release of the current branch.',
            'evidence'    => "Installed version: {$current_version} | Core update available: YES",
            'impact'      => 'Known vulnerabilities and lack of performance improvements.',
        ];
        $injected[] = 'wp_core_outdated';
    }

    if (!empty($injected)) {
        $diagnosis['findings'] = $findings;
    }

    return $injected;
}

// ─────────────────────────────────────────────────────────────────
// MAIN PIPELINE
// ─────────────────────────────────────────────────────────────────

/**
 * Runs the full pipeline for a verified site.
 *
 * Scanner API keys (VirusTotal, Sucuri) are optional and travel in the
 * request body from the user's browser. They are NOT stored server-side.
 * Empty keys mean "not configured" — the scanner is skipped and reported
 * as "not configured" in the forensic context.
 *
 * @param string $site_url         Target site URL
 * @param string $wpdiag_key       Auxiliary plugin key (already validated)
 * @param string $gemini_key       Gemini API key
 * @param string $run_id           Unique run identifier
 * @param string $vt_api_key       VirusTotal API key (optional)
 * @param string $sucuri_api_key   Sucuri API key (optional)
 * @return array                   The final $state object
 */
function run_pipeline(
    string $site_url,
    string $wpdiag_key,
    string $gemini_key,
    string $run_id,
    string $vt_api_key     = '',
    string $sucuri_api_key = ''
): array {

    if ($site_url === '' || $wpdiag_key === '' || $gemini_key === '' || $run_id === '') {
        error_log('[wpdiag] run_pipeline called with empty parameters');
        return [];
    }

    $state = initial_state($site_url, $run_id);
    _write_progress($state);

    // ── Step 0: technical context ─────────────────────────────
    $state['current_step'] = 0;
    $state['internal_log'][] = 'Collecting technical context';
    _write_progress($state);

    $verification = verify_plugin($site_url, $wpdiag_key);
    if (!$verification['ok']) return _fatal_error($state, $verification['message'], $verification['type']);

    $raw = $verification['data'];
    $ctx = prepare_context($raw);

    $state['context_raw']      = $raw;
    $state['context_prompt']   = $ctx['prompt'];
    $state['context_summary']  = $ctx['summary'];
    $state['estimated_tokens'] += $ctx['tokens'];
    $state['internal_log'][]   = "Context prepared ({$ctx['tokens']} estimated tokens)";

    // ── Step 1: Forensic agent ────────────────────────────────
    $state['current_step'] = 1;
    $state['internal_log'][] = 'Collecting forensic data';
    _write_progress($state);

    $forensics_raw = fetch_forensics($site_url, $wpdiag_key);
    $state['forensics_raw'] = $forensics_raw;

    if ($forensics_raw && !empty($forensics_raw['generated_at'])) {
        // Both scanners always return a structured array.
        // Empty keys produce ['status' => 'error', 'reason' => 'not_configured'].
        $vt_data     = vt_scan_url($site_url, $vt_api_key);
        $sucuri_data = sucuri_scan_url($site_url, $sucuri_api_key);

        $forensic_ctx = prepare_forensic_context($forensics_raw, $vt_data, $sucuri_data);
        $state['forensic_context'] = $forensic_ctx;

        $rf = forensic_agent($forensic_ctx, $gemini_key);
        $state['estimated_tokens'] += $rf['tokens'];

        if ($rf['ok']) {
            $state['forensic_agent'] = $rf['data'];
            $state['internal_log'][] = 'Forensic agent completed. Risk level: ' . ($rf['data']['risk_level'] ?? '?');
        } else {
            $state['errors'][]       = 'Forensic agent failed: ' . ($rf['error']['message'] ?? 'unknown error');
            $state['internal_log'][] = 'Forensic agent failed (non-fatal). Continuing without forensic data.';
            $state['forensic_agent'] = [
                'risk_level'            => 'none',
                'summary'               => 'No forensic data available.',
                'compromise_indicators' => [],
                'suspicious_files'      => [],
            ];
        }
    } else {
        $state['internal_log'][] = '/forensics endpoint does not respond. Continuing without forensic analysis.';
        $state['forensic_agent'] = [
            'risk_level'            => 'none',
            'summary'               => 'No forensic data available.',
            'compromise_indicators' => [],
            'suspicious_files'      => [],
        ];
    }
    _write_progress($state);

    // ── Step 2: Analyzer ──────────────────────────────────────
    $state['current_step'] = 2;
    _write_progress($state);

    $forensic_ctx_for_a1 = $state['forensic_context'] ?: 'No forensic data available.';
    $r1 = analyzer_agent($state['context_prompt'], $forensic_ctx_for_a1, $gemini_key);
    $state['estimated_tokens'] += $r1['tokens'];

    if (!$r1['ok']) return _handle_agent_error($state, 'analyzer', $r1['error']);

    $state['analyzer'] = $r1['data'];
    $state['internal_log'][] = 'Analyzer completed. Confidence: ' . ($r1['data']['confidence'] ?? '?');

    // ── Deterministic findings injection ──────────────────────
    if (!empty($state['context_raw'])) {
        $injected = _inject_deterministic_findings($r1['data'], $state['context_raw']);
        if (!empty($injected)) {
            $state['analyzer'] = $r1['data'];
            $state['internal_log'][] = 'Deterministic findings injected: ' . implode(', ', $injected);
        }
    }

    _write_progress($state);

    if (($r1['data']['confidence'] ?? '') === 'low') {
        $state['requires_human']        = true;
        $state['requires_human_reason'] = $r1['data']['requires_human_reason'] ?? 'Low confidence in the diagnosis.';
        $state['final_diagnosis']       = $r1['data'];
        $state['completed']             = true;
        $state['total_time']            = round(microtime(true) - $state['start_time'], 2);
        _write_progress($state);
        return $state;
    }

    // ── Step 3: Verifier ──────────────────────────────────────
    $state['current_step'] = 3;
    _write_progress($state);

    $r2 = verifier_agent(
        $state['context_prompt'],
        $forensic_ctx_for_a1,
        $r1['data'],
        $gemini_key
    );
    $state['estimated_tokens'] += $r2['tokens'];

    if (!$r2['ok']) return _handle_agent_error($state, 'verifier', $r2['error']);

    $state['verifier'] = $r2['data'];
    $verdict = $r2['data']['verdict'] ?? 'rejected';
    $state['internal_log'][] = 'Verifier completed. Verdict: ' . $verdict;
    _write_progress($state);

    if ($verdict === 'rejected') {
        $state['requires_human']        = true;
        $state['requires_human_reason'] = 'The verifier rejected the diagnosis.';
        $state['completed']             = true;
        $state['total_time']            = round(microtime(true) - $state['start_time'], 2);
        _write_progress($state);
        return $state;
    }

    $state['final_diagnosis'] = $r2['data']['final_diagnosis'];

    // ── Step 4: Writer ────────────────────────────────────────
    $state['current_step'] = 4;
    _write_progress($state);

    $r3 = writer_agent($state['final_diagnosis'], $gemini_key);
    $state['estimated_tokens'] += $r3['tokens'];

    if (!$r3['ok']) return _handle_agent_error($state, 'writer', $r3['error']);

    $state['writer']          = $r3['data'];
    $state['client_response'] = $r3['data']['response'] ?? '';
    $state['internal_log'][]  = 'Writer completed.';
    _write_progress($state);

    // ── Step 5: Operator ──────────────────────────────────────
    $state['current_step'] = 5;
    _write_progress($state);

    $r4 = operator_agent($state['final_diagnosis'], $site_url, $gemini_key);
    $state['estimated_tokens'] += $r4['tokens'];

    if (!$r4['ok']) {
        $state['errors'][]       = 'Operator failed: ' . ($r4['error']['message'] ?? 'unknown error');
        $state['actions']        = [];
        $state['internal_log'][] = 'Operator failed (non-fatal).';
    } else {
        $state['operator']       = $r4['data'];
        $state['actions']        = $r4['data']['actions'] ?? [];
        $state['internal_log'][] = 'Operator completed. Actions: ' . count($state['actions']);
    }

    // ── Guarantee that "generate_report" is always present ────
    $has_report = false;
    foreach ($state['actions'] as $a) {
        if (($a['id'] ?? '') === 'generate_report') { $has_report = true; break; }
    }
    if (!$has_report) {
        $state['actions'][] = [
            'id'                    => 'generate_report',
            'action'                => 'Generate printable report',
            'description'           => 'Document the technical and forensic findings for auditing and tracking.',
            'risk'                  => 'low',
            'requires_confirmation' => false,
            'executable'            => true,
            'manual_action'         => null,
        ];
        $state['internal_log'][] = 'generate_report added automatically (Operator omitted it).';
    }

    // ── Closure ───────────────────────────────────────────────
    if (!empty($r1['data']['requires_human'])) {
        $state['requires_human']        = true;
        $state['requires_human_reason'] = $r1['data']['requires_human_reason'] ?? 'The analyzer flagged this case for human review.';
    }

    $state['completed']   = true;
    $state['total_time']  = round(microtime(true) - $state['start_time'], 2);
    _write_progress($state);

    return $state;
}

// ─────────────────────────────────────────────────────────────────
// INTERNAL HELPERS
// ─────────────────────────────────────────────────────────────────

function _fatal_error(array $state, string $message, string $type): array {
    $state['fatal_error'] = ['type' => $type, 'message' => $message];
    $state['completed']   = true;
    $state['total_time']  = round(microtime(true) - $state['start_time'], 2);
    _write_progress($state);
    return $state;
}

function _handle_agent_error(array $state, string $agent, array $error): array {
    return _fatal_error($state, $error['user_message'] ?? $error['message'], $error['type']);
}