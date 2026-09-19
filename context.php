<?php
/**
 * WP Diagnostic AI — context.php
 * Preprocesses the raw JSON from the auxiliary plugin.
 * Deduplicates logs, summarizes plugins, filters noise.
 * Returns text ready to be inserted into a prompt.
 * Does not call the API or render HTML.
 */

if (!defined('ABSPATH')) exit;

/**
 * Main entry point.
 * Receives the decoded array from the auxiliary plugin and returns
 * a structured string for the agent prompts.
 *
 * @param array $raw  Decoded JSON from the wpdiag/v1/contexto endpoint
 * @return array {
 *   'prompt'  => string,   // text ready for the prompt
 *   'tokens'  => int,      // estimated token count of the context
 *   'summary' => array     // key data for the UI
 * }
 */
function prepare_context(array $raw): array {

    $sections = [];

    $sections[] = _section_site($raw['site']              ?? []);
    $sections[] = _section_server($raw['server']          ?? []);
    $sections[] = _section_wordpress($raw['wordpress']    ?? []);
    $sections[] = _section_plugins($raw['plugins']        ?? []);
    $sections[] = _section_themes($raw['themes']          ?? []);
    $sections[] = _section_admin_users($raw['admin_users'] ?? []);
    $sections[] = _section_updates($raw['updates']        ?? []);
    $sections[] = _section_database($raw['database']      ?? []);
    $sections[] = _section_critical_options($raw['critical_options'] ?? []);
    $sections[] = _section_logs($raw['php_logs']          ?? []);
    $sections[] = _section_posts($raw['recent_posts']     ?? []);

    $prompt = implode("\n\n", array_filter($sections));

    return [
        'prompt'  => $prompt,
        'tokens'  => (int) ceil(mb_strlen($prompt) / CONTEXT_CHARS_PER_TOKEN),
        'summary' => _extract_summary($raw),
    ];
}

// ─── Individual sections ──────────────────────────────────────

function _section_site(array $d): string {
    if (empty($d)) return '';
    return "## SITE INFORMATION\n"
        . "- Name: "   . ($d['name']     ?? 'N/A') . "\n"
        . "- URL: "    . ($d['url']      ?? 'N/A') . "\n"
        . "- Language: " . ($d['language'] ?? 'N/A') . "\n"
        . "- Timezone: " . ($d['timezone'] ?? 'N/A');
}

function _section_server(array $d): string {
    if (empty($d)) return '';

    $important_ext = ['curl', 'gd', 'imagick', 'mbstring', 'openssl', 'zip', 'exif', 'xml'];
    $present       = array_intersect($important_ext, $d['php_extensions'] ?? []);
    $missing       = array_diff($important_ext, $present);

    $out = "## SERVER\n"
        . "- PHP: "            . ($d['php_version']      ?? 'N/A') . "\n"
        . "- Server: "         . ($d['server_software']  ?? 'N/A') . "\n"
        . "- Memory limit: "   . ($d['memory_limit']     ?? 'N/A') . "\n"
        . "- Memory used: "    . ($d['memory_used']      ?? 'N/A') . "\n"
        . "- Max execution: "  . ($d['max_execution']    ?? 'N/A') . "\n"
        . "- Upload max: "     . ($d['upload_max']       ?? 'N/A') . "\n"
        . "- Architecture: "   . ($d['architecture']     ?? 'N/A') . "\n"
        . "- OS: "             . ($d['operating_system'] ?? 'N/A') . "\n"
        . "- Relevant PHP extensions present: " . (implode(', ', $present) ?: 'none') . "\n"
        . "- Relevant PHP extensions MISSING: " . (implode(', ', $missing) ?: 'none');

    return $out;
}

function _section_wordpress(array $d): string {
    if (empty($d)) return '';
    return "## WORDPRESS CORE\n"
        . "- WP version: "        . ($d['version']     ?? 'N/A') . "\n"
        . "- Multisite: "         . ($d['multisite']   ? 'Yes' : 'No') . "\n"
        . "- WP_DEBUG active: "   . ($d['debug_active'] ? 'YES (risk in production)' : 'No') . "\n"
        . "- WP_DEBUG_LOG: "      . ($d['debug_log']   ? 'YES' : 'No') . "\n"
        . "- SSL active: "        . ($d['ssl_active']  ? 'Yes' : 'No') . "\n"
        . "- Table prefix: "      . ($d['table_prefix'] ?? 'N/A') . "\n"
        . "- Permalink structure: " . ($d['permalink_structure'] ?? 'N/A') . "\n"
        . "- WP_CRON disabled: "  . ($d['wp_cron_disabled'] ? 'Yes' : 'No');
}

function _section_plugins(array $list): string {
    if (empty($list)) return '';

    $active   = array_filter($list, fn($p) => $p['active']);
    $inactive = array_filter($list, fn($p) => !$p['active']);

    $note = '';
    if (count($active) > CONTEXT_MAX_PLUGINS) {
        $active = array_slice($active, 0, CONTEXT_MAX_PLUGINS);
        $note   = "\n(List truncated to " . CONTEXT_MAX_PLUGINS . " active plugins)";
    }

    $active_lines = array_map(
        fn($p) => "  - {$p['name']} v{$p['version']} [{$p['path']}]",
        array_values($active)
    );

    $out = "## PLUGINS\n"
        . "- Total installed: " . count($list) . "\n"
        . "- Total active: "    . count($active) . "\n"
        . "- Total inactive: "  . count($inactive) . "\n"
        . "### Active plugins:\n"
        . implode("\n", $active_lines)
        . $note;

    return $out;
}

function _section_themes(array $d): string {
    if (empty($d)) return '';

    $active = $d['active'] ?? [];
    $parent = $active['parent'] ?? null;

    return "## THEMES\n"
        . "- Active theme: "     . ($active['name']    ?? 'N/A') . " v" . ($active['version'] ?? '?') . "\n"
        . "- Parent theme: "     . ($parent ?: 'None (standalone theme)') . "\n"
        . "- Installed themes: " . count($d['installed'] ?? []);
}

function _section_admin_users(array $list): string {
    if (empty($list)) return '';

    $lines = array_map(
        fn($u) => "  - {$u['login']} ({$u['email']}) — registered: {$u['registered']} — {$u['last_login']}",
        $list
    );

    return "## ADMINISTRATOR USERS (" . count($list) . " total)\n"
        . implode("\n", $lines);
}

function _section_updates(array $d): string {
    if (empty($d)) return '';
    return "## PENDING UPDATES\n"
        . "- WordPress core update available: " . ($d['core_available']   ? 'YES' : 'No') . "\n"
        . "- Plugins with pending update: "     . ($d['pending_plugins']  ?? 0);
}

function _section_database(array $d): string {
    if (empty($d)) return '';
    return "## DATABASE\n"
        . "- MySQL/MariaDB: "  . ($d['mysql_version'] ?? 'N/A') . "\n"
        . "- Total tables: "   . ($d['tables_total']  ?? 'N/A') . "\n"
        . "- Total size: "     . ($d['total_size']    ?? 'N/A') . "\n"
        . "- Charset: "        . ($d['charset']       ?? 'N/A') . "\n"
        . "- Collation: "      . ($d['collation']     ?? 'N/A');
}

function _section_critical_options(array $d): string {
    if (empty($d)) return '';

    $siteurl = $d['siteurl'] ?? '';
    $home    = $d['home']    ?? '';
    $mismatch = ($siteurl && $home && $siteurl !== $home)
        ? ' ⚠️ MISMATCH with home — possible infinite redirect'
        : '';

    return "## CRITICAL WORDPRESS OPTIONS\n"
        . "- siteurl: $siteurl$mismatch\n"
        . "- home: $home\n"
        . "- Admin email: "          . ($d['admin_email']     ?? 'N/A') . "\n"
        . "- Public indexing: "      . ($d['blogpublic'] ? 'Yes' : 'NO — blocked for search engines') . "\n"
        . "- Default role: "         . ($d['default_role']    ?? 'N/A') . "\n"
        . "- Open registration: "    . ($d['users_can_register'] ? 'YES (review if necessary)' : 'No') . "\n"
        . "- Comments open by default: " . ($d['comments_open'] ?? 'N/A');
}

function _section_logs(array $d): string {
    $lines = $d['lines'] ?? [];
    if (empty($lines)) {
        $note = $d['note'] ?? 'No logs available';
        return "## PHP LOGS\n- $note";
    }

    // Deduplicate: group repeated lines
    $count = [];
    foreach ($lines as $line) {
        // Normalize timestamps so the same error at different times groups together
        $normalized = preg_replace('/\[\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2} UTC\]/', '[TIMESTAMP]', $line);
        $count[$normalized] = ($count[$normalized] ?? 0) + 1;
    }

    $deduped = [];
    foreach ($count as $line => $times) {
        $suffix = $times > 1 ? " (repeated $times times)" : '';
        $deduped[] = "  " . trim($line) . $suffix;
    }

    // Keep the most recent / relevant after deduplication
    $deduped = array_slice($deduped, -CONTEXT_MAX_LOG_LINES);

    return "## PHP LOGS (latest entries, deduplicated)\n"
        . "- File: " . ($d['path'] ?? 'unknown') . "\n"
        . "### Entries:\n"
        . implode("\n", $deduped);
}

function _section_posts(array $list): string {
    if (empty($list)) return '';

    $lines = array_map(
        fn($p) => "  - [{$p['status']}] {$p['title']} ({$p['type']}) — {$p['date']}",
        $list
    );

    return "## RECENT POSTS\n" . implode("\n", $lines);
}

// ─── UI summary ───────────────────────────────────────────────

/**
 * Extracts key data from the context to show in the interface
 * before the agents finish (while the pipeline runs).
 */
function _extract_summary(array $raw): array {
    $active_plugins = count(array_filter(
        $raw['plugins'] ?? [],
        fn($p) => $p['active']
    ));

    return [
        'site_name'          => $raw['site']['name']                     ?? 'N/A',
        'url'                => $raw['site']['url']                      ?? 'N/A',
        'php_version'        => $raw['server']['php_version']            ?? 'N/A',
        'wp_version'         => $raw['wordpress']['version']             ?? 'N/A',
        'active_plugins'     => $active_plugins,
        'debug_active'       => $raw['wordpress']['debug_active']        ?? false,
        'ssl_active'         => $raw['wordpress']['ssl_active']          ?? false,
        'core_pending'       => !empty($raw['updates']['core_available']),
        'pending_plugins'    => (int)($raw['updates']['pending_plugins'] ?? 0),
        'admin_users'        => count($raw['admin_users']                ?? []),
        'db_size'            => $raw['database']['total_size']           ?? 'N/A',
        'generated_at'       => $raw['generated_at']                     ?? '',
    ];
}