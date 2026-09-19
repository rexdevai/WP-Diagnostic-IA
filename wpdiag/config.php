<?php
/**
 * WP Diagnostic AI — config.php
 * Global constants, API configuration, and static data.
 * No logic. Just data.
 */

if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');

// ─── Application ──────────────────────────────────────────────
define('WPDIAG_VERSION',  '1.0.0');
define('WPDIAG_BUILD',    '2026-09-19-102');
define('WPDIAG_NAME',     'WP Diagnostic AI');
define('WPDIAG_SLUG',     'wpdiag');
define('WPDIAG_UA',       'Mozilla/5.0 (compatible; WP-Diagnostic-AI/1.0)');

// ─── Session and temp files ───────────────────────────────────
define('WPDIAG_SESSION_PREFIX', 'wpdiag_');
define('WPDIAG_TEMP_TTL',       3600);

// ─── Gemini API ───────────────────────────────────────────────
define('GEMINI_ENDPOINT',   'https://generativelanguage.googleapis.com/v1beta/models/');
define('GEMINI_MODEL',      'gemini-3.1-flash-lite');
define('GEMINI_ACTION',     ':generateContent');
define('GEMINI_MAX_TOKENS', 4096);
define('GEMINI_TEMPERATURE',0.2);
define('GEMINI_TIMEOUT',    60);

// ─── Retries ──────────────────────────────────────────────────
define('GEMINI_MAX_RETRIES',    3);
define('GEMINI_BACKOFF_BASE',   5);

// ─── Context limits ───────────────────────────────────────────
define('CONTEXT_MAX_LOG_LINES',     50);
define('CONTEXT_MAX_PLUGINS',      100);
define('CONTEXT_CHARS_PER_TOKEN',    4);

// ─── Auxiliary plugin ─────────────────────────────────────────
define('WPDIAG_PLUGIN_SLUG',     'wpdiag-endpoint/wpdiag-endpoint.php');
define('WPDIAG_PLUGIN_FILENAME', 'wpdiag-endpoint.php');
define('WPDIAG_PLUGIN_DIR',      'wpdiag-endpoint');
define('WPDIAG_ENDPOINT_PATH',   '/wp-json/wpdiag/v1/context');
define('WPDIAG_FORENSICS_PATH',  '/wp-json/wpdiag/v1/forensics');
define('WPDIAG_STATUS_PATH',     '/wp-json/wpdiag/v1/status');
define('WPDIAG_KEY_HEADER',      'X-WPDiag-Key');

// ─── Forensics ────────────────────────────────────────────────
define('WPDIAG_FORENSICS_MAX',    30);
define('WPDIAG_FORENSICS_DAYS',   7);

// External scanner endpoints
define('WPDIAG_VT_ENDPOINT',      'https://www.virustotal.com/api/v3');
define('WPDIAG_SUCURI_ENDPOINT',  'https://sitecheck.sucuri.net/api/v3/');

// VirusTotal polling: the analysis is queued after submission and takes
// a few seconds to complete. We poll until status='completed' or timeout.
define('WPDIAG_VT_POLL_MAX_WAIT',  30);   // seconds total
define('WPDIAG_VT_POLL_INTERVAL',   3);   // seconds between polls

// ZIP verification workaround (for wp.org assets without published checksums)
define('WPDIAG_ZIP_VERIFY_MAX_BYTES', 20 * 1024 * 1024); // 20 MB max per ZIP
define('WPDIAG_ZIP_VERIFY_TIMEOUT',   30);               // seconds per download

// NOTE: External scanner API keys (VirusTotal, Sucuri) are provided by
// the user per-run — same pattern as the Gemini key. They travel in the
// POST body with each request and are NOT stored server-side.

// ─── Severities ───────────────────────────────────────────────
const WPDIAG_SEVERITIES = [
    'critical'      => ['label' => 'Critical',      'color' => '#f85149', 'badge' => 'badge-critical'],
    'high'          => ['label' => 'High',          'color' => '#d29922', 'badge' => 'badge-high'],
    'medium'        => ['label' => 'Medium',        'color' => '#2f81f7', 'badge' => 'badge-medium'],
    'low'           => ['label' => 'Low',           'color' => '#3fb950', 'badge' => 'badge-low'],
    'informational' => ['label' => 'Informational', 'color' => '#8b949e', 'badge' => 'badge-info'],
];

// ─── Categories ───────────────────────────────────────────────
const WPDIAG_CATEGORIES = [
    'security'      => 'Security',
    'performance'   => 'Performance',
    'configuration' => 'Configuration',
    'compatibility' => 'Compatibility',
    'no_issues'     => 'No issues detected',
];

// ─── Action risks ─────────────────────────────────────────────
const WPDIAG_RISKS = [
    'low'    => ['label' => 'Low',    'color' => '#3fb950'],
    'medium' => ['label' => 'Medium', 'color' => '#d29922'],
    'high'   => ['label' => 'High',   'color' => '#f85149'],
];

// ─── Allowed actions (closed list, Agent 4) ──────────────────
const WPDIAG_ALLOWED_ACTIONS = [
    'view_plugins'    => 'Open site plugins panel',
    'view_updates'    => 'Open updates panel',
    'view_logs'       => 'Open WordPress logs viewer',
    'copy_response'   => 'Copy response to clipboard',
    'generate_report' => 'Generate printable report',
];

// ─── Required fields per agent (validation) ───────────────────
const WPDIAG_FORENSIC_AGENT_FIELDS = [
    'risk_level', 'summary', 'compromise_indicators', 'suspicious_files',
];

const WPDIAG_AGENT1_FIELDS = [
    'main_cause', 'category', 'confidence',
    'severity', 'findings', 'forensic_findings',
    'alternative_hypotheses', 'missing_info', 'requires_human',
];

const WPDIAG_AGENT2_FIELDS = [
    'verdict', 'removed_findings',
    'added_findings', 'severity_corrections', 'final_diagnosis',
];

const WPDIAG_AGENT3_FIELDS = [
    'detected_tech_level', 'response', 'language',
];

const WPDIAG_AGENT4_FIELDS = [
    'actions',
];

// ─── Error messages by type ───────────────────────────────────
const WPDIAG_ERRORS = [
    'rate_limit'           => 'Rate limit reached. Retrying automatically.',
    'auth'                 => 'Invalid Gemini API key. Check your credentials.',
    'timeout'              => 'The API took too long to respond.',
    'malformed'            => 'The AI returned a response with invalid format.',
    'quota'                => 'Gemini daily quota exhausted. It resets at midnight (Pacific time).',
    'network'              => 'Connection error. Check your internet access.',
    'plugin_not_installed' => 'The WPDiag plugin is not installed on the target site.',
    'plugin_invalid_key'   => 'The plugin API key is incorrect.',
    'site_unreachable'     => 'Cannot connect to the site. Check the URL.',
    'wp_credentials'       => 'Wrong WordPress username or password.',
];