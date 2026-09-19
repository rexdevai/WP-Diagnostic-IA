<?php
/**
 * Plugin Name:       WPDiag Endpoint
 * Description:       Read-only REST endpoint for WP Diagnostic AI. Exposes technical + forensic context with integrity verification via checksums or official ZIP download. Modifies nothing.
 * Version:           1.4.0
 * Requires at least: 5.6
 * Requires PHP:      7.4
 * Author:            WP Diagnostic AI
 * License:           GPL-2.0-or-later
 * Text Domain:       wpdiag
 */

if (!defined('ABSPATH')) exit;

define('WPDIAG_EP_VERSION',    '1.4.0');
define('WPDIAG_EP_KEY_OPTION', 'wpdiag_endpoint_key');
define('WPDIAG_EP_KEY_HEADER', 'X-WPDiag-Key');
define('WPDIAG_EP_NS',         'wpdiag/v1');
define('WPDIAG_EP_MAX_LOG',    200);
define('WPDIAG_EP_FORENSICS_MAX',        30);
define('WPDIAG_EP_FORENSICS_DAYS',       7);
define('WPDIAG_EP_CHECKSUM_CACHE_TTL',   WEEK_IN_SECONDS);
define('WPDIAG_EP_CHECKSUM_CACHE_PREFIX', 'wpdiag_ck_v8_');
define('WPDIAG_EP_ZIP_MAX_BYTES',        20 * 1024 * 1024);
define('WPDIAG_EP_ZIP_TIMEOUT',          30);
define('WPDIAG_EP_ORIGIN_CACHE_TTL',     WEEK_IN_SECONDS);

/**
 * Critical patterns: almost never appear in legitimate plugins. If we
 * find them, we verify checksum. If it doesn't match or there's no
 * checksum, they are reported.
 */
const WPDIAG_EP_CRITICAL_PATTERNS = [
    'eval\s*\(',
    'shell_exec\s*\(',
    'system\s*\(',
    'passthru\s*\(',
    'exec\s*\(',
    'create_function\s*\(',
    'preg_replace\s*\(.*\/[a-z]*e[a-z]*[\'"]',
];

/**
 * Weak patterns: appear in legitimate plugins. Only report if the
 * checksum does NOT match the published version.
 */
const WPDIAG_EP_WEAK_PATTERNS = [
    'base64_decode\s*\(',
    'assert\s*\(',
    'file_put_contents\s*\(.*http',
    'curl_exec\s*\(.*\$_(GET|POST|REQUEST)',
];

const WPDIAG_EP_LEGIT_NAMES = [
    'loader', 'webfont', 'fonts', 'crypto', 'encryption', 'encoding', 'base64',
    'system-info', 'system_info', 'server-info', 'server_info',
    'docs-loader', 'documentation', 'file-system', 'filesystem',
    'http-client', 'curl-handler', 'cli-finder', 'php-cli',
];

const WPDIAG_EP_KNOWN_CRON_PREFIXES = [
    'wp_', 'akismet_', 'litespeed_', 'wpseo', 'wpseo_', 'bmi_', 'wai_',
    'mihdan_', 'mihdan-', 'wordfence_', 'et_', 'woocommerce_', 'wc_', 'yoast',
    'elementor', 'redirection_', 'action_scheduler', 'rank_math',
    'wpml_', 'sitepress', 'acf/', 'gravityforms_', 'wpforms_',
    'updraft_', 'backwpup_', 'duplicator_', 'monsterinsights_',
    'rocket_', 'really_simple_ssl', 'redux_', 'smush_', 'imagify_',
    'gim_', 'google_indexing', 'index-now', 'google-indexing',
];

// ─────────────────────────────────────────────────────────────────
// LIFECYCLE
// ─────────────────────────────────────────────────────────────────

register_activation_hook(__FILE__, 'wpdiag_ep_activate');

function wpdiag_ep_activate(): void {
    if (!get_option(WPDIAG_EP_KEY_OPTION)) {
        update_option(WPDIAG_EP_KEY_OPTION, wpdiag_ep_generate_key(), false);
    }
}

function wpdiag_ep_generate_key(): string {
    return wp_generate_password(32, false, false);
}

// ─────────────────────────────────────────────────────────────────
// HASH HELPERS
// ─────────────────────────────────────────────────────────────────

function wpdiag_ep_hash_matches_any(string $path, array $expected): bool {
    if (!file_exists($path)) return false;

    if (!empty($expected['md5']) && is_array($expected['md5'])) {
        $local_md5 = @md5_file($path);
        if ($local_md5 !== false && in_array($local_md5, $expected['md5'], true)) {
            return true;
        }
    }

    if (!empty($expected['sha256']) && is_array($expected['sha256'])) {
        if (function_exists('hash_file')) {
            $local_sha = @hash_file('sha256', $path);
            if ($local_sha !== false && in_array($local_sha, $expected['sha256'], true)) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Detects the algorithm from the expected hash length.
 * wp.org returns MD5 (32) but we support SHA1 and SHA256 for robustness.
 */
function wpdiag_ep_hash_algo(string $hash): ?string {
    $len = strlen($hash);
    if ($len === 32) return 'md5';
    if ($len === 40) return 'sha1';
    if ($len === 64) return 'sha256';
    return null;
}

/**
 * Computes the local hash of a file using the same algorithm
 * as the expected hash. Returns null if the algorithm is unrecognized.
 */
function wpdiag_ep_hash_local(string $path, string $expected_hash): ?string {
    $algo = wpdiag_ep_hash_algo($expected_hash);
    if ($algo === null) return null;
    return hash_file($algo, $path);
}

/**
 * Heuristic: does the file name suggest legitimate code?
 * Used to reduce severity of false positives in files without checksums.
 */
function wpdiag_ep_is_legit_name(string $path): bool {
    $basename = strtolower(basename($path));
    foreach (WPDIAG_EP_LEGIT_NAMES as $pattern) {
        if (strpos($basename, $pattern) !== false) {
            return true;
        }
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────
// ORIGIN DETECTION (wp.org vs premium)
// ─────────────────────────────────────────────────────────────────

/**
 * Checks whether a theme or plugin exists in the official wp.org repository.
 *
 * @return array {
 *   on_wporg: bool,
 *   data: array|null,
 *   error: string|null
 * }
 */
function wpdiag_ep_is_on_wporg(string $type, string $slug): array {
    if (!$slug) return ['on_wporg' => false, 'data' => null, 'error' => 'empty slug'];

    $cache_key = WPDIAG_EP_CHECKSUM_CACHE_PREFIX . 'wporg_' . md5($type . '_' . $slug);
    $cached    = get_transient($cache_key);
    if ($cached !== false) return $cached;

    $api_url = $type === 'theme'
        ? 'https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]=' . urlencode($slug)
        : 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=' . urlencode($slug);

    $resp = wp_remote_get($api_url, ['timeout' => 10]);

    if (is_wp_error($resp)) {
        $out = ['on_wporg' => false, 'data' => null, 'error' => $resp->get_error_message()];
        set_transient($cache_key, $out, HOUR_IN_SECONDS);
        return $out;
    }

    $code = wp_remote_retrieve_response_code($resp);
    if ($code !== 200) {
        $out = ['on_wporg' => false, 'data' => null, 'error' => 'http_' . $code];
        set_transient($cache_key, $out, WPDIAG_EP_ORIGIN_CACHE_TTL);
        return $out;
    }

    $body = json_decode(wp_remote_retrieve_body($resp), true);
    if (!is_array($body) || empty($body['slug'])) {
        $out = ['on_wporg' => false, 'data' => null, 'error' => 'no_data'];
        set_transient($cache_key, $out, WPDIAG_EP_ORIGIN_CACHE_TTL);
        return $out;
    }

    $out = ['on_wporg' => true, 'data' => $body, 'error' => null];
    set_transient($cache_key, $out, WPDIAG_EP_ORIGIN_CACHE_TTL);
    return $out;
}

// ─────────────────────────────────────────────────────────────────
// ZIP DOWNLOAD AND VERIFICATION
// ─────────────────────────────────────────────────────────────────

/**
 * Downloads the official wp.org ZIP, extracts it to a temp dir, and
 * computes MD5+SHA256 checksums for every file.
 *
 * Used as a fallback when the /plugin-checksums/ or /theme-checksums/
 * endpoint has no data for that version.
 *
 * @return array|false  Map [relative_file => ['md5' => [...], 'sha256' => [...]]]
 *                      or false on failure.
 */
function wpdiag_ep_checksums_from_zip(string $type, string $slug, string $version) {
    if (!$slug || !$version) return false;
    if (!class_exists('ZipArchive')) return false;

    if (!function_exists('wp_mkdir_p')) {
        require_once ABSPATH . 'wp-includes/functions.php';
    }

    $cache_key = WPDIAG_EP_CHECKSUM_CACHE_PREFIX . 'zip_' . md5($type . '_' . $slug . '_' . $version);
    $cached    = get_transient($cache_key);
    if ($cached !== false) return $cached;

    $base = $type === 'theme'
        ? 'https://downloads.wordpress.org/theme'
        : 'https://downloads.wordpress.org/plugin';

    $url = "{$base}/{$slug}.{$version}.zip";

    $tmp_zip = tempnam(sys_get_temp_dir(), 'wpdiag-');
    if (!$tmp_zip) {
        set_transient($cache_key, false, HOUR_IN_SECONDS);
        return false;
    }

    $resp = wp_remote_get($url, [
        'timeout'  => WPDIAG_EP_ZIP_TIMEOUT,
        'stream'   => true,
        'filename' => $tmp_zip,
    ]);

    if (is_wp_error($resp)) {
        @unlink($tmp_zip);
        set_transient($cache_key, false, HOUR_IN_SECONDS);
        return false;
    }

    $code = wp_remote_retrieve_response_code($resp);
    if ($code !== 200) {
        @unlink($tmp_zip);
        set_transient($cache_key, false, HOUR_IN_SECONDS);
        return false;
    }

    if (!file_exists($tmp_zip) || filesize($tmp_zip) > WPDIAG_EP_ZIP_MAX_BYTES) {
        @unlink($tmp_zip);
        set_transient($cache_key, false, HOUR_IN_SECONDS);
        return false;
    }

    $tmp_dir = trailingslashit(sys_get_temp_dir()) . 'wpdiag-' . wp_generate_password(12, false, false);
    if (!wp_mkdir_p($tmp_dir)) {
        @unlink($tmp_zip);
        set_transient($cache_key, false, HOUR_IN_SECONDS);
        return false;
    }

    $checksums = false;

    try {
        $zip = new ZipArchive();
        if ($zip->open($tmp_zip) !== true) {
            throw new Exception('Could not open ZIP');
        }

        $zip->extractTo($tmp_dir);
        $zip->close();
        @unlink($tmp_zip);

        $root_dir = $tmp_dir . '/' . $slug;
        if (!is_dir($root_dir)) {
            $root_dir = $tmp_dir;
        }

        $checksums  = [];
        $prefix_len = strlen($root_dir) + 1;
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root_dir, FilesystemIterator::SKIP_DOTS)
        );

        foreach ($it as $file) {
            if (!$file->isFile()) continue;

            $path = $file->getPathname();
            $rel  = substr($path, $prefix_len);
            $rel  = str_replace('\\', '/', $rel);

            $md5    = @md5_file($path);
            $sha256 = @hash_file('sha256', $path);

            if ($md5 === false) continue;

            $checksums[$rel] = [
                'md5'    => [$md5],
                'sha256' => $sha256 !== false ? [$sha256] : [],
            ];
        }
    } catch (Throwable $e) {
        $checksums = false;
    } finally {
        wpdiag_ep_rrmdir($tmp_dir);
        if (file_exists($tmp_zip)) @unlink($tmp_zip);
    }

    if (!is_array($checksums) || empty($checksums)) {
        set_transient($cache_key, false, HOUR_IN_SECONDS);
        return false;
    }

    set_transient($cache_key, $checksums, WPDIAG_EP_CHECKSUM_CACHE_TTL);
    return $checksums;
}

/**
 * Deletes a directory and all its contents recursively.
 */
function wpdiag_ep_rrmdir(string $dir): void {
    if (!is_dir($dir)) return;

    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($it as $file) {
        if ($file->isDir()) {
            @rmdir($file->getPathname());
        } else {
            @unlink($file->getPathname());
        }
    }
    @rmdir($dir);
}

// ─────────────────────────────────────────────────────────────────
// REST API
// ─────────────────────────────────────────────────────────────────

add_action('rest_api_init', 'wpdiag_ep_register_routes');

function wpdiag_ep_register_routes(): void {

    register_rest_route(WPDIAG_EP_NS, '/context', [
        'methods'             => 'GET',
        'callback'            => 'wpdiag_ep_handler_context',
        'permission_callback' => 'wpdiag_ep_validate_key',
    ]);

    register_rest_route(WPDIAG_EP_NS, '/forensics', [
        'methods'             => 'GET',
        'callback'            => 'wpdiag_ep_handler_forensics',
        'permission_callback' => 'wpdiag_ep_validate_key',
    ]);

    register_rest_route(WPDIAG_EP_NS, '/setup-key', [
        'methods'             => 'GET',
        'callback'            => 'wpdiag_ep_handler_setup_key',
        'permission_callback' => function () {
            return current_user_can('manage_options');
        },
    ]);

    register_rest_route(WPDIAG_EP_NS, '/status', [
        'methods'             => 'GET',
        'callback'            => fn() => [
            'ok'      => true,
            'plugin'  => 'wpdiag-endpoint',
            'version' => WPDIAG_EP_VERSION,
        ],
        'permission_callback' => '__return_true',
    ]);
}

function wpdiag_ep_validate_key(WP_REST_Request $req) {
    $stored_key = (string) get_option(WPDIAG_EP_KEY_OPTION, '');
    if ($stored_key === '') {
        return new WP_Error('wpdiag_no_key', 'The plugin has no API key generated.', ['status' => 500]);
    }

    $received_key = (string) $req->get_header(WPDIAG_EP_KEY_HEADER);
    if ($received_key === '' || !hash_equals($stored_key, $received_key)) {
        return new WP_Error('wpdiag_invalid_key', 'API key invalid or missing.', ['status' => 401]);
    }

    return true;
}

function wpdiag_ep_handler_setup_key(): WP_REST_Response {
    $key = get_option(WPDIAG_EP_KEY_OPTION);
    if (!$key) {
        $key = wpdiag_ep_generate_key();
        update_option(WPDIAG_EP_KEY_OPTION, $key, false);
    }
    return new WP_REST_Response(['api_key' => $key], 200);
}

// ─────────────────────────────────────────────────────────────────
// HANDLER: /context
// ─────────────────────────────────────────────────────────────────

function wpdiag_ep_handler_context(): WP_REST_Response {
    $ctx = [
        'site'             => wpdiag_ep_site(),
        'server'           => wpdiag_ep_server(),
        'wordpress'        => wpdiag_ep_wordpress(),
        'plugins'          => wpdiag_ep_plugins(),
        'themes'           => wpdiag_ep_themes(),
        'admin_users'      => wpdiag_ep_admin_users(),
        'updates'          => wpdiag_ep_updates(),
        'database'         => wpdiag_ep_database(),
        'critical_options' => wpdiag_ep_critical_options(),
        'php_logs'         => wpdiag_ep_logs(),
        'recent_posts'     => wpdiag_ep_recent_posts(),
        'generated_at'     => gmdate('c'),
    ];
    return new WP_REST_Response($ctx, 200);
}

// ─────────────────────────────────────────────────────────────────
// HANDLER: /forensics
// ─────────────────────────────────────────────────────────────────

function wpdiag_ep_handler_forensics(): WP_REST_Response {
    @set_time_limit(0);
    @ini_set('memory_limit', '256M');

    $core_integrity = wpdiag_ep_forensics_core();
    $stats          = [];
    $suspicious     = wpdiag_ep_forensics_suspicious_files($core_integrity, $stats);

    $data = [
        'core_integrity'      => $core_integrity,
        'plugin_integrity'    => wpdiag_ep_forensics_plugins(),
        'suspicious_files'    => $suspicious,
        'scan_stats'          => $stats,
        'recent_changes'      => wpdiag_ep_forensics_recent_changes(),
        'htaccess_suspicious' => wpdiag_ep_forensics_htaccess(),
        'htaccess_excerpt'    => '',
        'cron_suspicious'     => wpdiag_ep_forensics_cron(),
        'generated_at'        => gmdate('c'),
    ];
    return new WP_REST_Response($data, 200);
}

// ─────────────────────────────────────────────────────────────────
// CORE INTEGRITY
// ─────────────────────────────────────────────────────────────────

/**
 * Verifies WordPress core file integrity.
 *
 * Official API checksums include files that are NOT pure core:
 *  - wp-content/themes/twentytwentyfive/*  (bundled theme)
 *  - wp-content/plugins/akismet/*          (bundled plugin)
 *  - wp-content/plugins/hello.php          (bundled single-file plugin)
 *
 * We split them into independent buckets:
 *  - "core": only wp-admin/, wp-includes/ and root files
 *  - "themes_bundled": themes that ship with WP
 *  - "plugins_bundled": plugins that ship with WP
 */
function wpdiag_ep_forensics_core(): array {
    global $wp_version;

    $checksums = wpdiag_ep_get_checksums_core($wp_version, get_locale());
    if (empty($checksums)) {
        return ['checked' => false, 'error' => 'Could not obtain official checksums.'];
    }

    $core_mismatches    = [];
    $core_missing       = [];
    $themes_mismatches  = [];
    $plugins_mismatches = [];

    $themes_files  = [];
    $plugins_files = [];

    foreach ($checksums as $file => $expected) {
        if (strpos($file, 'wp-content/themes/') === 0) {
            if (preg_match('#^wp-content/themes/([^/]+)/(.+)$#', $file, $m)) {
                $themes_files[$m[1]][$m[2]] = $expected;
            }
            continue;
        }

        if (strpos($file, 'wp-content/plugins/') === 0) {
            if (preg_match('#^wp-content/plugins/([^/]+)/(.+)$#', $file, $m)) {
                $plugins_files[$m[1]][$m[2]] = $expected;
            }
            continue;
        }

        $path = ABSPATH . $file;
        if (!file_exists($path)) {
            $core_missing[] = $file;
            continue;
        }
        if (!wpdiag_ep_hash_matches_any($path, $expected)) {
            $core_mismatches[] = ['file' => $file, 'expected' => wpdiag_ep_hash_summary($expected)];
        }
    }

    foreach ($themes_files as $slug => $files) {
        $theme = wp_get_theme($slug);
        if (!$theme->exists()) continue;

        $version = $theme->get('Version');
        if (!$version) continue;

        $theme_checksums = wpdiag_ep_get_checksums_theme($slug, $version);
        if (empty($theme_checksums)) continue;

        foreach ($files as $rel => $expected_core) {
            $path = ABSPATH . "wp-content/themes/{$slug}/{$rel}";
            if (!file_exists($path)) continue;

            $expected = $theme_checksums[$rel] ?? null;
            if ($expected === null) continue;

            if (!wpdiag_ep_hash_matches_any($path, $expected)) {
                $themes_mismatches[] = [
                    'theme'    => $slug,
                    'version'  => $version,
                    'file'     => $rel,
                    'expected' => wpdiag_ep_hash_summary($expected),
                ];
            }
        }
    }

    foreach ($plugins_files as $slug => $files) {
        $version = wpdiag_ep_get_plugin_version($slug);
        if (!$version) continue;

        $plugin_checksums = wpdiag_ep_get_checksums_plugin($slug, $version);
        if (empty($plugin_checksums)) continue;

        foreach ($files as $rel => $expected_core) {
            $path = ABSPATH . "wp-content/plugins/{$slug}/{$rel}";
            if (!file_exists($path)) continue;

            $expected = $plugin_checksums[$rel] ?? null;
            if ($expected === null) continue;

            if (!wpdiag_ep_hash_matches_any($path, $expected)) {
                $plugins_mismatches[] = [
                    'plugin'   => $slug,
                    'version'  => $version,
                    'file'     => $rel,
                    'expected' => wpdiag_ep_hash_summary($expected),
                ];
            }
        }
    }

    return [
        'checked'            => true,
        'version'            => $wp_version,
        'total'              => count($checksums),
        'mismatches'         => array_slice($core_mismatches,    0, WPDIAG_EP_FORENSICS_MAX),
        'missing'            => array_slice($core_missing,       0, WPDIAG_EP_FORENSICS_MAX),
        'themes_mismatches'  => array_slice($themes_mismatches,  0, WPDIAG_EP_FORENSICS_MAX),
        'plugins_mismatches' => array_slice($plugins_mismatches, 0, WPDIAG_EP_FORENSICS_MAX),
    ];
}

/**
 * Returns a readable string to display in JSON: "md5:abc123...,sha256:def456..."
 * Each hash is truncated to 12 chars to avoid bloating the response.
 */
function wpdiag_ep_hash_summary(array $expected): string {
    $parts = [];
    foreach ($expected as $algo => $hashes) {
        if (!is_array($hashes) || empty($hashes)) continue;
        foreach ($hashes as $h) {
            if (!is_string($h)) continue;
            $parts[] = $algo . ':' . substr($h, 0, 12);
        }
    }
    return implode(',', $parts);
}

function wpdiag_ep_get_checksums_core(string $version, string $locale): array {
    $cache_key = WPDIAG_EP_CHECKSUM_CACHE_PREFIX . 'core_' . md5($version . '_' . $locale);
    $checksums = get_transient($cache_key);

    if ($checksums !== false) return $checksums;

    $url = 'https://api.wordpress.org/core/checksums/1.0/?' . http_build_query([
        'version' => $version,
        'locale'  => $locale,
    ]);
    $resp = wp_remote_get($url, ['timeout' => 15]);
    if (is_wp_error($resp)) return [];

    $body = json_decode(wp_remote_retrieve_body($resp), true);
    if (!is_array($body)) return [];

    $checksums = [];
    if (isset($body['checksums']) && is_array($body['checksums'])) {
        foreach ($body['checksums'] as $file => $hash) {
            if (is_string($hash) && $hash !== '') {
                $checksums[$file] = ['md5' => [$hash], 'sha256' => []];
            }
        }
    }

    if (!empty($checksums)) {
        set_transient($cache_key, $checksums, WPDIAG_EP_CHECKSUM_CACHE_TTL);
    }

    return $checksums;
}

// ─────────────────────────────────────────────────────────────────
// ACTIVE PLUGIN INTEGRITY
// ─────────────────────────────────────────────────────────────────

function wpdiag_ep_forensics_plugins(): array {
    if (!function_exists('get_plugins')) require_once ABSPATH . 'wp-admin/includes/plugin.php';

    $active     = (array) get_option('active_plugins', []);
    $all        = get_plugins();
    $mismatches = [];

    foreach ($active as $path) {
        if (!isset($all[$path])) continue;
        $info    = $all[$path];
        $slug    = explode('/', $path)[0] ?? '';
        $version = $info['Version'] ?? '';
        if (!$slug || !$version) continue;

        $checksums = wpdiag_ep_get_checksums_plugin($slug, $version);
        if (empty($checksums)) continue;

        $plugin_dir = WP_PLUGIN_DIR . '/' . dirname($path);

        foreach ($checksums as $file => $expected) {
            $path_full = $plugin_dir . '/' . $file;
            if (!file_exists($path_full)) continue;
            if (!wpdiag_ep_hash_matches_any($path_full, $expected)) {
                $mismatches[] = [
                    'plugin'  => $slug,
                    'version' => $version,
                    'file'    => $file,
                    'reason'  => 'checksum mismatch',
                ];
            }
        }
    }

    return ['mismatches' => array_slice($mismatches, 0, WPDIAG_EP_FORENSICS_MAX)];
}

/**
 * Parses the wp.org response and returns:
 *   [file => ['md5' => [...], 'sha256' => [...]]]
 *
 * Actual wp.org structure:
 *   {
 *     "plugin": "...",
 *     "version": "...",
 *     "files": {
 *       "file.php": { "md5": ["hash1"], "sha256": ["hash2"] }
 *     }
 *   }
 */
function wpdiag_ep_parse_checksums_response(array $body): array {
    if (isset($body['files']) && is_array($body['files'])) {
        $body = $body['files'];
    }

    $out = [];
    foreach ($body as $file => $value) {
        $hashes = ['md5' => [], 'sha256' => []];

        if (is_string($value) && $value !== '') {
            $len = strlen($value);
            if ($len === 32)      $hashes['md5'][]    = $value;
            elseif ($len === 64)  $hashes['sha256'][] = $value;
            else                  $hashes['md5'][]    = $value;
        } elseif (is_array($value)) {
            foreach ($value as $algo => $list) {
                if (!in_array($algo, ['md5', 'sha256'], true)) continue;
                if (is_string($list) && $list !== '') {
                    $hashes[$algo][] = $list;
                } elseif (is_array($list)) {
                    foreach ($list as $h) {
                        if (is_string($h) && $h !== '') {
                            $hashes[$algo][] = $h;
                        }
                    }
                }
            }
        }

        if (!empty($hashes['md5']) || !empty($hashes['sha256'])) {
            $out[$file] = $hashes;
        }
    }
    return $out;
}

function wpdiag_ep_get_checksums_plugin(string $slug, string $version): array {
    if (!$slug || !$version) return [];

    $cache_key = WPDIAG_EP_CHECKSUM_CACHE_PREFIX . 'plugin_' . md5($slug . '_' . $version);
    $checksums = get_transient($cache_key);

    if ($checksums !== false) return is_array($checksums) ? $checksums : [];

    $url  = "https://downloads.wordpress.org/plugin-checksums/{$slug}/{$version}.json";
    $resp = wp_remote_get($url, ['timeout' => 15]);

    if (!is_wp_error($resp) && wp_remote_retrieve_response_code($resp) === 200) {
        $body = json_decode(wp_remote_retrieve_body($resp), true);
        if (is_array($body)) {
            $checksums = wpdiag_ep_parse_checksums_response($body);
            if (!empty($checksums)) {
                set_transient($cache_key, $checksums, WPDIAG_EP_CHECKSUM_CACHE_TTL);
                return $checksums;
            }
        }
    }

    $wporg = wpdiag_ep_is_on_wporg('plugin', $slug);
    if (!empty($wporg['on_wporg'])) {
        $from_zip = wpdiag_ep_checksums_from_zip('plugin', $slug, $version);
        if (is_array($from_zip) && !empty($from_zip)) {
            set_transient($cache_key, $from_zip, WPDIAG_EP_CHECKSUM_CACHE_TTL);
            return $from_zip;
        }
    }

    set_transient($cache_key, [], HOUR_IN_SECONDS);
    return [];
}

function wpdiag_ep_get_checksums_theme(string $slug, string $version): array {
    if (!$slug || !$version) return [];

    $cache_key = WPDIAG_EP_CHECKSUM_CACHE_PREFIX . 'theme_' . md5($slug . '_' . $version);
    $checksums = get_transient($cache_key);

    if ($checksums !== false) return is_array($checksums) ? $checksums : [];

    $url  = "https://downloads.wordpress.org/theme-checksums/{$slug}/{$version}.json";
    $resp = wp_remote_get($url, ['timeout' => 15]);

    if (!is_wp_error($resp) && wp_remote_retrieve_response_code($resp) === 200) {
        $body = json_decode(wp_remote_retrieve_body($resp), true);
        if (is_array($body)) {
            $checksums = wpdiag_ep_parse_checksums_response($body);
            if (!empty($checksums)) {
                set_transient($cache_key, $checksums, WPDIAG_EP_CHECKSUM_CACHE_TTL);
                return $checksums;
            }
        }
    }

    $wporg = wpdiag_ep_is_on_wporg('theme', $slug);
    if (!empty($wporg['on_wporg'])) {
        $from_zip = wpdiag_ep_checksums_from_zip('theme', $slug, $version);
        if (is_array($from_zip) && !empty($from_zip)) {
            set_transient($cache_key, $from_zip, WPDIAG_EP_CHECKSUM_CACHE_TTL);
            return $from_zip;
        }
    }

    set_transient($cache_key, [], HOUR_IN_SECONDS);
    return [];
}

// ─────────────────────────────────────────────────────────────────
// LOCATION IDENTIFICATION
// ─────────────────────────────────────────────────────────────────

function wpdiag_ep_identify_file(string $abs_path): array {
    $abs_path = wp_normalize_path($abs_path);
    $base     = wp_normalize_path(ABSPATH);
    $rel      = ltrim(str_replace($base, '', $abs_path), '/');

    if (preg_match('#^wp-(admin|includes)/#', $rel)) {
        return ['type' => 'core', 'slug' => '', 'version' => '', 'rel_path' => $rel];
    }

    if (!str_contains($rel, '/') || preg_match('#^[^/]+\.php$#', $rel)) {
        return ['type' => 'core', 'slug' => '', 'version' => '', 'rel_path' => $rel];
    }

    $content_dir = wp_normalize_path(WP_CONTENT_DIR);
    $rel_content = ltrim(str_replace($content_dir, '', $abs_path), '/');

    if (preg_match('#^uploads/#', $rel_content)) {
        return ['type' => 'uploads', 'slug' => '', 'version' => '', 'rel_path' => $rel_content];
    }

    if (preg_match('#^mu-plugins/#', $rel_content)) {
        $sub = preg_replace('#^mu-plugins/#', '', $rel_content);
        return ['type' => 'mu-plugin', 'slug' => '', 'version' => '', 'rel_path' => $sub];
    }

    if (preg_match('#^plugins/([^/]+)/(.+)$#', $rel_content, $m)) {
        $slug = $m[1];
        $version = wpdiag_ep_get_plugin_version($slug);
        return ['type' => 'plugin', 'slug' => $slug, 'version' => $version, 'rel_path' => $m[2]];
    }

    if (preg_match('#^themes/([^/]+)/(.+)$#', $rel_content, $m)) {
        $slug = $m[1];
        $theme = wp_get_theme($slug);
        $version = $theme->exists() ? $theme->get('Version') : '';
        return ['type' => 'theme', 'slug' => $slug, 'version' => $version, 'rel_path' => $m[2]];
    }

    return ['type' => 'other', 'slug' => '', 'version' => '', 'rel_path' => $rel];
}

function wpdiag_ep_get_plugin_version(string $slug): string {
    if (!function_exists('get_plugins')) require_once ABSPATH . 'wp-admin/includes/plugin.php';
    static $cache = null;

    if ($cache === null) {
        $cache = [];
        foreach (get_plugins() as $path => $info) {
            $s = explode('/', $path)[0] ?? '';
            if ($s && !isset($cache[$s])) {
                $cache[$s] = $info['Version'] ?? '';
            }
        }
    }

    return $cache[$slug] ?? '';
}

// ─────────────────────────────────────────────────────────────────
// SUSPICIOUS FILES
// ─────────────────────────────────────────────────────────────────

function wpdiag_ep_forensics_suspicious_files(array $core_integrity, array &$stats): array {
    $stats = [
        'files_scanned'            => 0,
        'with_patterns'            => 0,
        'discarded_by_checksum'    => 0,
        'discarded_by_rule'        => 0,
        'discarded_vendor'         => 0,
        'reported'                 => 0,
    ];

    $dirs = [
        WP_CONTENT_DIR . '/plugins',
        WP_CONTENT_DIR . '/themes',
        WP_CONTENT_DIR . '/mu-plugins',
        WP_CONTENT_DIR . '/uploads',
    ];

    $core_mismatches = [];
    foreach ($core_integrity['mismatches'] ?? [] as $m) {
        $core_mismatches[wp_normalize_path(ABSPATH . $m['file'])] = true;
    }
    if (!empty($core_mismatches)) {
        $dirs[] = wp_normalize_path(ABSPATH . 'wp-admin');
        $dirs[] = wp_normalize_path(ABSPATH . WPINC);
    }

    $suspicious  = [];
    $max_report  = WPDIAG_EP_FORENSICS_MAX;

    foreach ($dirs as $dir) {
        if (!is_dir($dir)) continue;

        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
            );
        } catch (Exception $e) { continue; }

        foreach ($it as $file) {
            if ($stats['reported'] >= $max_report) break 2;
            if ($file->getExtension() !== 'php') continue;

            $path = wp_normalize_path($file->getPathname());

            if (preg_match('#/(vendor|vendor_prefixed|node_modules|bower_components)/#', $path)) {
                $stats['discarded_vendor']++;
                continue;
            }

            // Exclude our own plugin from forensic analysis
            if (strpos($path, '/wpdiag-endpoint/') !== false) {
                continue;
            }

            $stats['files_scanned']++;

            $content = @file_get_contents($path, false, null, 0, 8192);
            if ($content === false) continue;

            $found_pattern = null;
            $pattern_type  = null;

            foreach (WPDIAG_EP_CRITICAL_PATTERNS as $p) {
                if (preg_match('/' . $p . '/', $content)) {
                    $found_pattern = $p;
                    $pattern_type  = 'critical';
                    break;
                }
            }
            if ($found_pattern === null) {
                foreach (WPDIAG_EP_WEAK_PATTERNS as $p) {
                    if (preg_match('/' . $p . '/', $content)) {
                        $found_pattern = $p;
                        $pattern_type  = 'weak';
                        break;
                    }
                }
            }

            if ($found_pattern === null) continue;
            $stats['with_patterns']++;

            $loc = wpdiag_ep_identify_file($path);

            if ($loc['type'] === 'core' && isset($core_mismatches[$path])) {
                $suspicious[] = [
                    'path'         => str_replace(wp_normalize_path(ABSPATH), '', $path),
                    'reason'       => "core modified + {$pattern_type} pattern: {$found_pattern}",
                    'severity'     => 'critical',
                    'pattern'      => $found_pattern,
                    'pattern_type' => $pattern_type,
                    'location'     => 'core@' . ($core_integrity['version'] ?? '?'),
                    'verification' => 'checksum_mismatch',
                    'origin'       => 'core',
                ];
                $stats['reported']++;
                continue;
            }

            $checksums = [];
            $origin    = 'unknown';

            if ($loc['type'] === 'plugin' && $loc['slug'] && $loc['version']) {
                $wporg = wpdiag_ep_is_on_wporg('plugin', $loc['slug']);
                if (!empty($wporg['on_wporg'])) {
                    $checksums = wpdiag_ep_get_checksums_plugin($loc['slug'], $loc['version']);
                    $origin    = !empty($checksums) ? 'wporg_verified' : 'wporg_unverified';
                } else {
                    $origin = 'premium_or_custom';
                }
            } elseif ($loc['type'] === 'theme' && $loc['slug'] && $loc['version']) {
                $wporg = wpdiag_ep_is_on_wporg('theme', $loc['slug']);
                if (!empty($wporg['on_wporg'])) {
                    $checksums = wpdiag_ep_get_checksums_theme($loc['slug'], $loc['version']);
                    $origin    = !empty($checksums) ? 'wporg_verified' : 'wporg_unverified';
                } else {
                    $origin = 'premium_or_custom';
                }
            } elseif ($loc['type'] === 'mu-plugin') {
                $origin = 'custom_mu_plugin';
            } elseif ($loc['type'] === 'uploads') {
                $origin = 'suspicious_zone';
            }

            $has_checksums = !empty($checksums);
            $expected      = $checksums[$loc['rel_path']] ?? null;
            $checksum_ok   = false;

            if ($expected !== null) {
                $checksum_ok = wpdiag_ep_hash_matches_any($path, $expected);
            }

            $report        = false;
            $severity      = 'low';
            $verification  = 'no_checksum';
            $extra_reason  = '';

            if ($checksum_ok) {
                $stats['discarded_by_checksum']++;
                continue;
            }

            $legit_name = wpdiag_ep_is_legit_name($path);

            switch ($pattern_type) {
                case 'critical':
                    $report = true;
                    if ($has_checksums && $expected !== null) {
                        $verification = 'checksum_mismatch';
                        $severity     = 'high';
                        $extra_reason = ' | checksum does not match wp.org';
                    } elseif ($has_checksums && $expected === null) {
                        $verification = 'extra_file';
                        $severity     = 'high';
                        $extra_reason = ' | file not listed in wp.org';
                    } elseif ($origin === 'premium_or_custom') {
                        $verification = 'premium_unverifiable';
                        $severity     = 'informational';
                        $extra_reason = ' | premium/custom component — not verifiable via wp.org';
                    } elseif ($origin === 'wporg_unverified') {
                        $verification = 'wporg_unverifiable';
                        $severity     = 'medium';
                        $extra_reason = ' | wp.org does not expose checksums or ZIP for this version';
                    } elseif ($legit_name) {
                        $verification = 'no_checksum_legit_name';
                        $severity     = 'low';
                        $extra_reason = ' | no checksum + filename suggests legitimate code';
                    } else {
                        $verification = 'no_checksum';
                        $severity     = 'medium';
                        $extra_reason = ' | no official checksum';
                    }
                    break;

                case 'weak':
                    if ($has_checksums && $expected !== null) {
                        $report       = true;
                        $verification = 'checksum_mismatch';
                        $severity     = 'medium';
                        $extra_reason = ' | checksum does not match wp.org';
                    } else {
                        $stats['discarded_by_rule']++;
                        continue 2;
                    }
                    break;
            }

            if (!$report) {
                $stats['discarded_by_rule']++;
                continue;
            }

            if ($loc['type'] === 'uploads') {
                $severity     = 'critical';
                $verification = 'unverifiable_zone';
                $extra_reason = ' | PHP in uploads';
                $origin       = 'suspicious_zone';
            }

            if ($loc['type'] === 'mu-plugin') {
                $verification = 'premium_unverifiable';
                $severity     = 'medium';
                $extra_reason = ' | custom mu-plugin without checksums';
                $origin       = 'custom_mu_plugin';
            }

            $suspicious[] = [
                'path'         => str_replace(wp_normalize_path(ABSPATH), '', $path),
                'reason'       => "{$pattern_type} pattern: {$found_pattern}{$extra_reason}",
                'severity'     => $severity,
                'pattern'      => $found_pattern,
                'pattern_type' => $pattern_type,
                'location'     => $loc['type'] . ($loc['slug'] ? ":{$loc['slug']}" : '') . ($loc['version'] ? "@{$loc['version']}" : ''),
                'verification' => $verification,
                'origin'       => $origin,
            ];
            $stats['reported']++;
        }
    }

    return $suspicious;
}

// ─────────────────────────────────────────────────────────────────
// RECENT CHANGES
// ─────────────────────────────────────────────────────────────────

function wpdiag_ep_forensics_recent_changes(): array {
    $dirs = [
        WP_CONTENT_DIR . '/plugins',
        WP_CONTENT_DIR . '/themes',
        WP_CONTENT_DIR . '/mu-plugins',
    ];

    $since    = time() - (WPDIAG_EP_FORENSICS_DAYS * DAY_IN_SECONDS);
    $recent   = [];
    $max      = WPDIAG_EP_FORENSICS_MAX;

    foreach ($dirs as $dir) {
        if (!is_dir($dir)) continue;
        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
            );
        } catch (Exception $e) { continue; }

        foreach ($it as $file) {
            if ($file->getExtension() !== 'php') continue;
            $mtime = $file->getMTime();
            if ($mtime >= $since) {
                $recent[] = [
                    'path'  => str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($file->getPathname())),
                    'mtime' => gmdate('Y-m-d H:i:s', $mtime),
                    'size'  => $file->getSize(),
                ];
            }
        }
    }

    usort($recent, fn($a, $b) => strcmp($b['mtime'], $a['mtime']));
    return array_slice($recent, 0, $max);
}

// ─────────────────────────────────────────────────────────────────
// .HTACCESS AND CRON
// ─────────────────────────────────────────────────────────────────

function wpdiag_ep_forensics_htaccess(): bool {
    $ht = ABSPATH . '.htaccess';
    if (!file_exists($ht)) return false;

    $content = @file_get_contents($ht);
    if ($content === false) return false;

    $suspicious = [
        '/php_value\s+auto_prepend_file/i',
        '/RewriteRule.*https?:\/\//i',
        '/<FilesMatch.*\.(php|phtml)/i',
        '/AddType\s+application\/x-httpd-php/i',
        '/php_value\s+allow_url_include/i',
    ];

    foreach ($suspicious as $pattern) {
        if (preg_match($pattern, $content)) return true;
    }
    return false;
}

/**
 * Detects cron hooks that don't belong to known plugins/themes.
 * Filters by popular plugin prefixes to avoid false positives.
 */
function wpdiag_ep_forensics_cron(): array {
    $cron = _get_cron_array();
    if (!is_array($cron)) return [];

    $core_hooks = [
        'wp_version_check', 'wp_update_plugins', 'wp_update_themes',
        'wp_scheduled_delete', 'wp_scheduled_auto_draft_delete',
        'wp_cron', 'do_pings', 'delete_expired_transients',
        'recovery_mode_clean_expired_keys', 'upgrader_scheduled_cleanup',
    ];

    $suspicious = [];
    foreach ($cron as $timestamp => $hooks) {
        foreach ($hooks as $hook => $_) {
            if (in_array($hook, $core_hooks, true)) continue;

            $known = false;
            foreach (WPDIAG_EP_KNOWN_CRON_PREFIXES as $prefix) {
                if (strpos($hook, $prefix) === 0) {
                    $known = true;
                    break;
                }
            }
            if ($known) continue;

            $suspicious[] = $hook;
        }
    }

    return array_values(array_unique(array_slice($suspicious, 0, 15)));
}

// ─────────────────────────────────────────────────────────────────
// CONTEXT COLLECTORS
// ─────────────────────────────────────────────────────────────────

function wpdiag_ep_site(): array {
    return [
        'name'     => get_bloginfo('name'),
        'url'      => home_url(),
        'language' => get_bloginfo('language'),
        'timezone' => wp_timezone_string(),
    ];
}

function wpdiag_ep_server(): array {
    return [
        'php_version'      => PHP_VERSION,
        'server_software'  => $_SERVER['SERVER_SOFTWARE']  ?? 'unknown',
        'memory_limit'     => ini_get('memory_limit'),
        'memory_used'      => defined('WP_MEMORY_LIMIT') ? WP_MEMORY_LIMIT : 'unknown',
        'max_execution'    => ini_get('max_execution_time'),
        'upload_max'       => ini_get('upload_max_filesize'),
        'architecture'     => php_uname('m'),
        'operating_system' => php_uname('s'),
        'php_extensions'   => array_values(array_filter(
            get_loaded_extensions(),
            fn($e) => in_array(strtolower($e), [
                'curl','gd','imagick','mbstring','openssl','zip','exif','xml',
                'json','mysqli','pdo_mysql','intl','bcmath'
            ], true)
        )),
    ];
}

function wpdiag_ep_wordpress(): array {
    global $wpdb;
    return [
        'version'             => get_bloginfo('version'),
        'multisite'           => is_multisite(),
        'debug_active'        => defined('WP_DEBUG') && WP_DEBUG,
        'debug_log'           => defined('WP_DEBUG_LOG') && WP_DEBUG_LOG,
        'ssl_active'          => is_ssl(),
        'table_prefix'        => $wpdb->prefix,
        'permalink_structure' => get_option('permalink_structure') ?: 'plain',
        'wp_cron_disabled'    => defined('DISABLE_WP_CRON') && DISABLE_WP_CRON,
    ];
}

function wpdiag_ep_plugins(): array {
    if (!function_exists('get_plugins')) require_once ABSPATH . 'wp-admin/includes/plugin.php';

    $all    = get_plugins();
    $active = (array) get_option('active_plugins', []);

    $out = [];
    foreach ($all as $path => $info) {
        $out[] = [
            'name'    => (string) ($info['Name']    ?? 'Unknown'),
            'version' => (string) ($info['Version'] ?? '0'),
            'path'    => (string) $path,
            'active'  => in_array($path, $active, true),
        ];
    }
    return $out;
}

function wpdiag_ep_themes(): array {
    $current = wp_get_theme();
    $parent  = $current->parent();

    $installed = [];
    foreach (wp_get_themes() as $slug => $t) {
        $installed[] = ['slug' => $slug, 'name' => $t->get('Name'), 'version' => $t->get('Version')];
    }

    return [
        'active' => [
            'name'    => $current->get('Name'),
            'version' => $current->get('Version'),
            'parent'  => $parent ? $parent->get('Name') : null,
        ],
        'installed' => $installed,
    ];
}

function wpdiag_ep_admin_users(): array {
    $users = get_users(['role' => 'administrator', 'number' => 20, 'orderby' => 'registered', 'order' => 'ASC']);

    $out = [];
    foreach ($users as $u) {
        $last = get_user_meta($u->ID, 'last_login', true);
        $out[] = [
            'login'      => $u->user_login,
            'email'      => $u->user_email,
            'registered' => $u->user_registered,
            'last_login' => $last ?: 'unknown',
        ];
    }
    return $out;
}

function wpdiag_ep_updates(): array {
    wp_update_plugins();

    $core    = get_site_transient('update_core');
    $plugins = get_site_transient('update_plugins');

    $core_available = false;
    if ($core && !empty($core->updates)) {
        foreach ($core->updates as $u) {
            if (($u->response ?? '') === 'upgrade') { $core_available = true; break; }
        }
    }

    $pending_plugins = 0;
    if ($plugins && !empty($plugins->response)) $pending_plugins = count($plugins->response);

    return ['core_available' => $core_available, 'pending_plugins' => $pending_plugins];
}

function wpdiag_ep_database(): array {
    global $wpdb;

    $charset   = $wpdb->get_var("SELECT @@character_set_database");
    $collation = $wpdb->get_var("SELECT @@collation_database");
    $tables    = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM information_schema.TABLES WHERE table_schema = %s", DB_NAME));
    $bytes     = (int) $wpdb->get_var($wpdb->prepare("SELECT SUM(data_length + index_length) FROM information_schema.TABLES WHERE table_schema = %s", DB_NAME));

    return [
        'mysql_version' => $wpdb->db_version(),
        'tables_total'  => $tables,
        'total_size'    => wpdiag_ep_human_bytes($bytes),
        'charset'       => (string) $charset,
        'collation'     => (string) $collation,
    ];
}

function wpdiag_ep_critical_options(): array {
    return [
        'siteurl'             => get_option('siteurl'),
        'home'                => get_option('home'),
        'admin_email'         => get_option('admin_email'),
        'blogpublic'          => (int) get_option('blog_public'),
        'default_role'        => get_option('default_role'),
        'users_can_register'  => (int) get_option('users_can_register'),
        'comments_open'       => (int) get_option('default_comment_status') === 1
                                 || get_option('default_comment_status') === 'open',
    ];
}

function wpdiag_ep_logs(): array {
    $lines = [];
    $path  = '';
    $note  = '';

    if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
        $wp_log = WP_DEBUG_LOG === true ? WP_CONTENT_DIR . '/debug.log' : WP_DEBUG_LOG;
        if (is_readable($wp_log)) {
            $path  = $wp_log;
            $lines = wpdiag_ep_tail_file($wp_log, WPDIAG_EP_MAX_LOG);
        } else {
            $note = 'WP_DEBUG_LOG active but the file is not readable: ' . $wp_log;
        }
    }

    if (empty($lines)) {
        $sys_log = ini_get('error_log');
        if ($sys_log && is_readable($sys_log) && filesize($sys_log) > 0) {
            $path  = $sys_log;
            $lines = wpdiag_ep_tail_file($sys_log, WPDIAG_EP_MAX_LOG);
        }
    }

    if (empty($lines) && $note === '') {
        $note = 'No accessible logs.';
    }

    return ['lines' => $lines, 'path' => $path ?: 'unknown', 'note' => $note];
}

function wpdiag_ep_tail_file(string $path, int $max_lines): array {
    $size = @filesize($path);
    if (!$size) return [];

    $read = min($size, 512 * 1024);
    $fh = @fopen($path, 'rb');
    if (!$fh) return [];

    fseek($fh, -$read, SEEK_END);
    $content = fread($fh, $read);
    fclose($fh);

    $all = preg_split('/\r?\n/', (string) $content);
    $all = array_values(array_filter($all, fn($l) => trim($l) !== ''));

    return array_slice($all, -$max_lines);
}

function wpdiag_ep_recent_posts(): array {
    $posts = get_posts([
        'numberposts' => 5,
        'post_status' => ['publish', 'draft', 'pending', 'private'],
        'post_type'   => ['post', 'page'],
        'orderby'     => 'modified',
        'order'       => 'DESC',
    ]);

    $out = [];
    foreach ($posts as $p) {
        $out[] = [
            'status' => $p->post_status,
            'title'  => wp_strip_all_tags($p->post_title) ?: '(no title)',
            'type'   => $p->post_type,
            'date'   => $p->post_modified,
        ];
    }
    return $out;
}

function wpdiag_ep_human_bytes(int $bytes): string {
    $u = ['B','KB','MB','GB','TB'];
    $i = 0;
    while ($bytes >= 1024 && $i < count($u) - 1) { $bytes /= 1024; $i++; }
    return round($bytes, 2) . ' ' . $u[$i];
}

// ─────────────────────────────────────────────────────────────────
// ADMIN PANEL
// ─────────────────────────────────────────────────────────────────

add_action('admin_menu', 'wpdiag_ep_menu');
add_action('admin_post_wpdiag_ep_regen', 'wpdiag_ep_regenerate_handler');

function wpdiag_ep_menu(): void {
    add_options_page('WP Diagnostics', 'WP Diagnostics', 'manage_options', 'wpdiag-endpoint', 'wpdiag_ep_render_admin');
}

function wpdiag_ep_regenerate_handler(): void {
    if (!current_user_can('manage_options')) wp_die('Insufficient permissions.');
    check_admin_referer('wpdiag_ep_regen');

    update_option(WPDIAG_EP_KEY_OPTION, wpdiag_ep_generate_key(), false);

    wp_safe_redirect(add_query_arg('regenerated', '1', wp_get_referer() ?: admin_url('options-general.php?page=wpdiag-endpoint')));
    exit;
}

function wpdiag_ep_render_admin(): void {
    if (!current_user_can('manage_options')) return;

    $key = (string) get_option(WPDIAG_EP_KEY_OPTION, '');
    if ($key === '') {
        $key = wpdiag_ep_generate_key();
        update_option(WPDIAG_EP_KEY_OPTION, $key, false);
    }

    $endpoint = rest_url(WPDIAG_EP_NS . '/context');
    ?>
    <div class="wrap">
        <h1>WP Diagnostics</h1>

        <?php if (!empty($_GET['regenerated'])): ?>
            <div class="notice notice-success is-dismissible"><p>API key regenerated.</p></div>
        <?php endif; ?>

        <p>This plugin exposes <strong>read-only</strong> endpoints with technical information about the site. It is used by the external interface <em>WP Diagnostic AI</em>.</p>

        <h2>API Key</h2>
        <p>Copy this key and paste it in the external interface:</p>
        <p>
            <input type="text" value="<?= esc_attr($key) ?>" readonly
                   style="font-family:monospace;width:420px;padding:6px"
                   onclick="this.select()">
        </p>

        <form method="post" action="<?= esc_url(admin_url('admin-post.php')) ?>">
            <?php wp_nonce_field('wpdiag_ep_regen'); ?>
            <input type="hidden" name="action" value="wpdiag_ep_regen">
            <?php submit_button('Regenerate key', 'secondary', 'submit', false); ?>
        </form>

        <h2>Endpoints</h2>
        <ul style="list-style:disc;padding-left:20px">
            <li><code><?= esc_html(rest_url(WPDIAG_EP_NS . '/context')) ?></code> — technical context</li>
            <li><code><?= esc_html(rest_url(WPDIAG_EP_NS . '/forensics')) ?></code> — forensic analysis with checksum verification</li>
            <li><code><?= esc_html(rest_url(WPDIAG_EP_NS . '/status')) ?></code> — public verification</li>
            <li><code><?= esc_html(rest_url(WPDIAG_EP_NS . '/setup-key')) ?></code> — key reader (admin)</li>
        </ul>
        <p>Header required on protected endpoints: <code><?= esc_html(WPDIAG_EP_KEY_HEADER) ?></code></p>

        <h2>What this plugin does NOT do</h2>
        <ul style="list-style:disc;padding-left:20px">
            <li>Does not modify files, plugins, themes, or the database</li>
            <li>Does not expose passwords or post content</li>
        </ul>
    </div>
    <?php
}