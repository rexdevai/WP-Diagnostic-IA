# WP Diagnostic AI

> WordPress diagnostic tool — A multi-agent AI pipeline that audits any WordPress site for security, configuration, performance, and file integrity issues, then produces a client-ready report and prioritized action list.

**Author:** Rexdevai
**Version:** 1.0.0
**Requires:** WordPress 5.6+ · PHP 7.4+ · Gemini API key
**License:** Private / All rights reserved

---

## What it does

WP Diagnostic AI is a two-part system:

1. **A PHP web interface** (this project) that orchestrates a five-agent AI pipeline against any WordPress site.
2. **A lightweight auxiliary plugin** (`wpdiag-endpoint`) that is installed on the target site and exposes read-only REST endpoints with technical and forensic context.

The interface connects to the target site, collects server/WordPress/plugin/user data, runs forensic integrity checks, sends everything through Gemini, and returns a structured diagnosis. It never modifies the target site.

---

## Key features

**Diagnostic pipeline**
- Five-agent chain: Forensic → Analyzer → Verifier → Writer → Operator
- Every agent sees the original context, not just the previous agent's output
- Each agent has a single responsibility (no cross-verification)
- Live pipeline progress via Server-Sent Events (SSE) with polling fallback
- Automatic early-stop when the Analyzer has low confidence or the Verifier rejects

**Forensic analysis**
- WordPress core integrity via official wp.org checksums
- Bundled theme and plugin integrity (separated from core)
- Active plugin integrity via downloads.wordpress.org/plugin-checksums/
- ZIP-based fallback: downloads the official ZIP and computes MD5+SHA256 locally when wp.org has no published checksums
- Origin detection per component: `wporg_verified`, `wporg_unverified`, `premium_or_custom`, `custom_mu_plugin`, `suspicious_zone`
- Suspicious pattern scan (`eval`, `system`, `exec`, etc.) with vendor folder exclusion
- Filtered cron scan (known plugin prefixes excluded)
- Excludes the auxiliary plugin itself from its own forensic scan

**External scanners (user-provided API keys)**
- VirusTotal and Sucuri SiteCheck
- Both are entered by the user in the connection screen (`Advanced options`)
- Both are optional; leave empty to skip
- Results appear in a dedicated **External security scans** panel in the report
- VirusTotal uses polling with stability detection (handles the API's "in_progress forever" behaviour) and reports partial stats when the analysis doesn't complete
- The Writer mentions clean scans in the client-facing reply

**Automation**
- Automatic installation of the auxiliary plugin on the target site via admin panel automation (login → upload → activate → fetch key)
- No manual file upload required
- Automatic retrieval of the WPDiag Key after activation
- Deterministic findings injection from context flags (WP_DEBUG, WP_CRON, SSL, extensions, core update) — no reliance on the LLM for those

**Output**
- Unified diagnosis with technical and forensic findings
- External security scans panel (only shown when at least one scanner is configured)
- Client-ready reply automatically written in the target site's language
- Prioritized action list with risk levels and executable/manual separation
- Printable report
- Raw forensic data panel for auditing

**Interface**
- Vanilla PHP + vanilla JS. No frameworks, no build step
- Dark UI, self-contained
- Works on any modern browser (desktop and mobile)
- Fallback manual flow for sites that block automated login

---

## Architecture

    ┌───────────────────────────────────────┐
    │  PHP Interface (this project)         │
    │  ─────────────────────────────────    │
    │  index.php    · Router + SSE + worker │
    │  pipeline.php · Orchestrator          │
    │  agents.php   · 5 agents              │
    │  forensics.php· External scanners     │
    │  context.php  · Context preprocessing │
    │  gemini.php   · Gemini HTTP client    │
    │  render.php   · HTML view             │
    │  app.js       · Pipeline client       │
    │  style.css    · UI                    │
    └──────────────────┬────────────────────┘
                       │  HTTPS · REST
                       ▼
    ┌───────────────────────────────────────┐
    │  Target WordPress site                │
    │  ─────────────────────────────────    │
    │  wpdiag-endpoint.php (v1.4.0)         │
    │   /wp-json/wpdiag/v1/status           │
    │   /wp-json/wpdiag/v1/context          │
    │   /wp-json/wpdiag/v1/forensics        │
    │   /wp-json/wpdiag/v1/setup-key        │
    └───────────────────────────────────────┘

---

## Requirements

**On the interface server**
- PHP 7.4+ with `curl`, `json`, `session`
- Optional: `ZipArchive` (only needed for the automatic plugin installation feature)
- Outbound HTTPS to generativelanguage.googleapis.com and downloads.wordpress.org
- Write access to `sys_get_temp_dir()`

**On the target WordPress site**
- WordPress 5.6+ (REST API and Application Passwords)
- PHP 7.4+
- HTTPS (Basic Auth requires it)
- An administrator account with a valid App Password (for automatic installation) or the ability to install the plugin manually

**External services (all user-provided, none stored server-side)**
- **Gemini API key** — required. Create one for free in Google AI Studio: https://aistudio.google.com/apikey. The key must have access to the `gemini-3.1-flash-lite` model.
- **VirusTotal API key** — optional. Free tier: sign up at https://www.virustotal.com/gui/my-apikey. Limit: 4 requests/min, 500/day.
- **Sucuri SiteCheck API key** — optional. Requires a paid plan.

---

## Installation

1. Upload the `wpdiag/` folder to your web server, under a publicly accessible path (e.g. https://your-server.com/wpdiag/).

2. Ensure `sys_get_temp_dir()` is writable by the PHP process.

3. Ensure the `wp-plugin/wpdiag-endpoint.php` file exists inside the project (it is served automatically as ZIP or PHP when the target site needs it).

4. Open https://your-server.com/wpdiag/ in a browser.

5. Enter the target site URL and your Gemini API key.

6. (Optional) Expand **Advanced options** and paste your VirusTotal and/or Sucuri API keys to enable the external scanners.

7. If the auxiliary plugin is not installed on the target site, provide the WordPress admin username and password — the interface will install it automatically.

8. If the auxiliary plugin is already installed, provide the WPDiag Key (found in Settings › WP Diagnostics on the target site).

9. Run the pipeline.

---

## External scanners (user-provided)

Both external scanners are configured **per run**, from the interface — not from `config.php`. The keys:

- Travel in the POST body of the `run` request
- Are never written to disk, session, or log on the interface server
- Only affect that single run

**VirusTotal** — free tier available. The scanner submits the URL, then polls the analysis endpoint until either:
- The status is `completed`, or
- The engine count stops growing for two consecutive polls (stability detection), or
- The polling window (`WPDIAG_VT_POLL_MAX_WAIT`, default 90s) expires

If the window expires with partial data, the interface reports a `partial` result with the stats collected so far, rather than discarding everything.

**Sucuri SiteCheck** — requires a paid plan. If the key is invalid or the plan is missing, the scanner reports `invalid_key` and the section shows an informative message.

**When no keys are provided**, the section is hidden from the report entirely.

---

## Manual fallback

If the target site blocks automated login (2FA, security plugins, host restrictions), the interface offers a manual flow:

1. Download the plugin ZIP via `?action=plugin_zip`.
2. Install it manually on the target site.
3. Copy the WPDiag Key from Settings › WP Diagnostics.
4. Paste it in the interface and run the pipeline.

---

## File structure

    wpdiag/
    ├── index.php                     Entry point · router · SSE · async worker
    ├── config.php                    Constants, palette, agent field definitions
    ├── gemini.php                    HTTP client for Gemini API
    ├── context.php                   Context preprocessing for prompts
    ├── forensics.php                 External scanners + forensic context builder
    ├── agents.php                    The 5 agents (prompts + output parsing)
    ├── pipeline.php                  Orchestrator + deterministic findings injection
    ├── render.php                    HTML view
    ├── assets/
    │   ├── style.css                 UI styles
    │   └── app.js                    Pipeline client
    └── wp-plugin/
        └── wpdiag-endpoint.php       Auxiliary plugin (installed on target site)

---

## Security notes

- All credentials entered in the interface (WordPress username, password, WPDiag Key, Gemini key, VirusTotal key, Sucuri key) are held in browser memory only. They are sent to the interface server on each request but never written to disk, log, or session.
- The auxiliary plugin on the target site is strictly read-only. It never modifies files, plugins, themes, the database, or WordPress configuration.
- The WPDiag Key is validated with `hash_equals()` on every request.
- The pipeline never executes destructive actions on the target site. The Operator agent only **suggests** actions; all of them in v1.0.0 are either UI-level (open a panel, copy to clipboard, print report) or `manual_action` entries that require the user to act on the server.
- All user-visible output is escaped before rendering (`htmlspecialchars` on PHP side, DOM `textContent` on JS side).
- The interface does not accept uploads from the browser; the plugin ZIP is generated server-side on demand from the source file.

---

## Compatibility

- WordPress 5.6+
- PHP 7.4+
- Any modern browser (Chrome, Firefox, Safari, Edge)
- Works with or without LiteSpeed, Cloudflare, or other CDNs — but **purge cache** after installing the auxiliary plugin to avoid cached 404s on `/status`
- No external framework required (no Composer, no npm, no build step)

---

## Credits

Developed by **Rexdevai**.
Architecture, agent design, prompts, and integration flows defined by the author.

---

*[ES] Versión en español disponible en [README.es.md](./README.es.md)*