<?php
/**
 * WP Diagnostic AI — render.php
 * Single HTML file. No business logic.
 * All IDs must match app.js — do not rename.
 *
 * v1.0.10 — Restored: Google AI Studio link + API/model hint for Gemini field.
 */
if (!defined('ABSPATH')) exit;
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?= htmlspecialchars(WPDIAG_NAME) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap">
<link rel="stylesheet" href="<?= wpdiag_asset_url('assets/style.css') ?>">
</head>
<body>

<div class="wrap">

  <header class="app-header">
    <h1>WP Diagnostic <span>AI</span></h1>
    <span class="version">v<?= htmlspecialchars(WPDIAG_VERSION) ?></span>
  </header>

  <div id="banner" class="banner hidden" role="alert"></div>

  <div id="status-bar" class="status-bar">
    <span class="dot"></span>
    <span id="status-text">Ready to connect</span>
    <span class="right" id="status-right"></span>
  </div>

  <!-- ═══════════════════════════════════════════════════════════
       VIEW 1 · Initial connection (URL + Gemini key + optional scanners)
       ═══════════════════════════════════════════════════════════ -->
  <section class="view active" data-view="connect">
    <h2>Connect WordPress site</h2>
    <p class="lead">
      Enter the site URL and your Gemini API Key. We'll check whether the auxiliary
      plugin is active before asking for anything else.
    </p>

    <form id="form-connect" class="card-form" autocomplete="off">
      <div class="field full">
        <label for="site_url">WordPress site URL</label>
        <input type="url" id="site_url" name="site_url"
               placeholder="https://example.com" required pattern="https?://.+">
        <span class="hint">Must include the protocol (https://).</span>
      </div>

      <div class="field full">
        <label for="gemini_key">Gemini API Key</label>
        <input type="password" id="gemini_key" name="gemini_key"
               placeholder="AIza..." required autocomplete="new-password">
        <span class="hint">
          API: <strong>Google Gemini</strong> · model:
          <code><?= htmlspecialchars(GEMINI_MODEL) ?></code> ·
          used only in your session, not stored on the target site.
          <br>
          Get a free key at
          <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noopener">Google AI Studio ↗</a>.
        </span>
      </div>

      <details class="advanced-options full">
        <summary>Advanced options — external scanners (optional)</summary>
        <p class="muted small" style="margin:8px 0 14px">
          These are external malware scanners. If you provide your own API keys, their results
          will be added to the forensic analysis. Leave empty to skip them.
        </p>

        <div class="field">
          <label for="vt_api_key">VirusTotal API Key</label>
          <input type="password" id="vt_api_key" name="vt_api_key"
                 placeholder="Free — get it at virustotal.com" autocomplete="new-password">
          <span class="hint">
            Free tier: 4 req/min.
            Get a key at
            <a href="https://www.virustotal.com/gui/my-apikey" target="_blank" rel="noopener">virustotal.com ↗</a>.
          </span>
        </div>

        <div class="field">
          <label for="sucuri_api_key">Sucuri API Key</label>
          <input type="password" id="sucuri_api_key" name="sucuri_api_key"
                 placeholder="Requires paid plan" autocomplete="new-password">
          <span class="hint">
            Requires a paid Sucuri plan. Leave empty if you don't have one.
            More info at
            <a href="https://sucuri.net/" target="_blank" rel="noopener">sucuri.net ↗</a>.
          </span>
        </div>
      </details>

      <div class="actions">
        <button type="submit" class="primary">Check site</button>
      </div>
    </form>
  </section>

  <!-- ═══════════════════════════════════════════════════════════
       VIEW 2 · Plugin installed → request credentials to fetch the key
       ═══════════════════════════════════════════════════════════ -->
  <section class="view" data-view="key">
    <h2>Get WPDiag Key</h2>
    <p class="lead">
      The auxiliary plugin is already active on the site. Enter your administrator
      credentials and we'll retrieve the API key automatically.
    </p>

    <div class="banner info" style="margin-bottom:20px">
      <span class="icon">🔒</span>
      <div class="body">
        <strong>Credentials are used once and discarded.</strong><br>
        They are only used to read the API key from the site's admin panel.
      </div>
    </div>

    <form id="form-key" class="card-form" autocomplete="off">
      <div class="field">
        <label for="wp_user_key">WordPress username</label>
        <input type="text" id="wp_user_key" name="wp_user"
               placeholder="admin" required autocomplete="off">
        <span class="hint">Site administrator.</span>
      </div>

      <div class="field">
        <label for="wp_password_key">WordPress password</label>
        <input type="password" id="wp_password_key" name="wp_password"
               placeholder="••••••••••••" required autocomplete="new-password">
        <span class="hint">Your regular wp-admin password.</span>
      </div>

      <div class="actions">
        <button type="submit" class="primary">Get key and run</button>
        <button type="button" class="ghost btn-back-connect">Back</button>
      </div>
    </form>

    <details style="margin-top:22px">
      <summary class="muted small" style="cursor:pointer">Prefer to paste the key manually?</summary>
      <div style="margin-top:12px;padding-left:8px">
        <form id="form-key-manual" class="card-form" autocomplete="off">
          <div class="field full">
            <label for="wpdiag_key_manual">WPDiag Key</label>
            <input type="text" id="wpdiag_key_manual" name="wpdiag_key"
                   placeholder="32 alphanumeric characters" required
                   autocomplete="off" spellcheck="false">
            <span class="hint">Find it under Settings › WP Diagnostics on the site.</span>
          </div>
          <div class="actions">
            <button type="submit" class="primary">Use this key</button>
          </div>
        </form>
      </div>
    </details>
  </section>

  <!-- ═══════════════════════════════════════════════════════════
       VIEW 3 · Plugin not detected → automatic installation
       ═══════════════════════════════════════════════════════════ -->
  <section class="view" data-view="install">
    <h2>Install auxiliary plugin</h2>
    <p class="lead">
      The auxiliary plugin is not active on the site. Enter your administrator
      credentials and we'll install it automatically.
    </p>

    <div class="banner info" style="margin-bottom:20px">
      <span class="icon">🔒</span>
      <div class="body">
        <strong>Credentials are used once and discarded.</strong>
      </div>
    </div>

    <form id="form-install" class="card-form" autocomplete="off">
      <div class="field">
        <label for="wp_user">WordPress username</label>
        <input type="text" id="wp_user" name="wp_user"
               placeholder="admin" required autocomplete="off">
        <span class="hint">Must have administrator role.</span>
      </div>

      <div class="field">
        <label for="wp_password">WordPress password</label>
        <input type="password" id="wp_password" name="wp_password"
               placeholder="••••••••••••" required autocomplete="new-password">
        <span class="hint">Your regular wp-admin password (not an App Password).</span>
      </div>

      <div class="actions">
        <button type="submit" class="primary">Install and continue</button>
        <button type="button" class="ghost btn-back-connect">Back</button>
      </div>
    </form>

    <details style="margin-top:22px">
      <summary class="muted small" style="cursor:pointer">Prefer to install it manually? (fallback)</summary>
      <div style="margin-top:12px;padding-left:8px">
        <p class="muted small" style="margin-bottom:10px">
          Download the ZIP and install it from <strong>Plugins › Add New › Upload Plugin</strong>.
          Then enter the WPDiag Key on the next screen.
        </p>
        <a class="button-link" href="?action=plugin_zip" download>⬇ Download wpdiag-endpoint.zip</a>
      </div>
    </details>
  </section>

  <!-- ═══════════════════════════════════════════════════════════
       VIEW 4 · Pipeline in progress / results
       ═══════════════════════════════════════════════════════════ -->
  <section class="view" data-view="pipeline">
    <h2>Pipeline running</h2>
    <p class="lead">
      Each agent sees the site's original context, not just the previous agent's output.
      Expand any card to inspect its raw output.
    </p>

    <div id="site-summary" class="site-summary" aria-live="polite"></div>

    <div class="log-stream" id="log-stream"
         aria-live="polite" aria-label="Pipeline event log"></div>

    <div class="pipeline" id="pipeline"></div>

    <section id="result-diag" class="result-section hidden">
      <h3>
        Diagnosis
        <span class="pill" id="diag-sev">—</span>
        <span class="pill" id="diag-conf">—</span>
        <span class="pill" id="diag-cat">—</span>
        <button class="ghost copy-btn" id="btn-print">Print</button>
      </h3>
      <p class="diag-cause" id="diag-cause"></p>
      <ul class="findings" id="diag-findings"></ul>

      <div id="diag-forensics-wrap" class="hidden">
        <h4 style="margin:20px 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);display:flex;align-items:center;gap:8px">
          <span>🔍 Forensic findings</span>
        </h4>
        <ul class="findings" id="diag-forensics"></ul>
      </div>

      <details id="raw-forensics" class="raw-forensics hidden">
        <summary>View raw forensic data (as returned by the site)</summary>
        <div class="raw-content">

          <div class="raw-section" id="raw-stats-wrap">
            <h5>Scan statistics</h5>
            <div id="raw-stats"></div>
          </div>

          <div class="raw-section" id="raw-core-wrap">
            <h5>WordPress core integrity</h5>
            <div id="raw-core"></div>
          </div>

          <div class="raw-section" id="raw-plugins-wrap">
            <h5>Plugin integrity</h5>
            <div id="raw-plugins"></div>
          </div>

          <div class="raw-section" id="raw-suspicious-wrap">
            <h5>Suspicious files (malware patterns)</h5>
            <div id="raw-suspicious"></div>
          </div>

          <div class="raw-section" id="raw-recent-wrap">
            <h5>Recently modified files</h5>
            <div id="raw-recent"></div>
          </div>

          <div class="raw-section" id="raw-cron-wrap">
            <h5>Suspicious cron tasks</h5>
            <div id="raw-cron"></div>
          </div>

          <div class="raw-section" id="raw-htaccess-wrap">
            <h5>.htaccess</h5>
            <div id="raw-htaccess"></div>
          </div>

          <div class="raw-section">
            <h5>Forensic agent summary (agent 00)</h5>
            <div id="raw-forensic-agent"></div>
          </div>

        </div>
      </details>
    </section>

    <section id="result-reply" class="result-section customer-reply hidden">
      <h3>
        Suggested client response
        <button class="ghost copy-btn" id="btn-copy-reply">Copy</button>
      </h3>
      <div class="content"></div>
    </section>

    <section id="result-actions" class="result-section hidden">
      <h3>Suggested actions</h3>
      <div class="actions-grid" id="actions-grid"></div>
    </section>

    <div class="actions" style="margin-top:24px">
      <button class="ghost hidden" id="btn-new-run">New analysis</button>
    </div>
  </section>

</div>

<script src="<?= wpdiag_asset_url('assets/app.js') ?>"></script>
</body>
</html>