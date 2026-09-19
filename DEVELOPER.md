# WP Diagnostic AI — Developer Documentation

**Version:** 1.0.0
**Author:** Rexdevai

This document describes the internal architecture, agent design, HTTP contracts, forensic verification flow, pipeline orchestration, and integration points used by WP Diagnostic AI.

---

## Architecture overview

WP Diagnostic AI is composed of two independent codebases that communicate over HTTPS via REST.

    ┌─────────────────────────────────────────────────────┐
    │  Interface (this project)                           │
    │                                                     │
    │  index.php    · Router · SSE · Async worker         │
    │  pipeline.php · Orchestrator                        │
    │  agents.php   · 5 agents (pure functions)           │
    │  forensics.php· External scanners + context builder │
    │  context.php  · Context preprocessing               │
    │  gemini.php   · Gemini HTTP client                  │
    │  render.php   · Single HTML view                    │
    │  app.js       · Pipeline client                     │
    │  style.css    · UI                                  │
    └──────────────────────┬──────────────────────────────┘
                           │ HTTPS REST + SSE
                           ▼
    ┌─────────────────────────────────────────────────────┐
    │  Target WordPress site                              │
    │                                                     │
    │  wpdiag-endpoint.php  (auxiliary plugin v1.4.0)     │
    │   · /status         (public, no auth)               │
    │   · /context        (X-WPDiag-Key)                  │
    │   · /forensics      (X-WPDiag-Key)                  │
    │   · /setup-key      (manage_options)                │
    └─────────────────────────────────────────────────────┘

The interface never modifies the target site. All target-site endpoints are strictly read-only.

---

## File structure

    wpdiag/
    ├── index.php                     Entry point
    ├── config.php                    Constants + static data
    ├── gemini.php                    HTTP client for Gemini
    ├── context.php                   Context preprocessing
    ├── forensics.php                 External scanners + forensic builder
    ├── agents.php                    The 5 agents
    ├── pipeline.php                  Orchestrator
    ├── render.php                    HTML view
    ├── assets/
    │   ├── style.css                 UI styles
    │   └── app.js                    Pipeline client
    └── wp-plugin/
        └── wpdiag-endpoint.php       Auxiliary plugin

---

## Component map

| Component | File | Responsibility |
|-----------|------|----------------|
| Config | `config.php` | Constants, palette, error messages, allowed actions, agent field contracts, VT polling config |
| Gemini client | `gemini.php` | HTTP requests to Gemini with retry + error classification |
| Context | `context.php` | Preprocesses the auxiliary plugin's JSON into structured prompt text |
| Forensics | `forensics.php` | VirusTotal + Sucuri integration, forensic prompt builder, scanner result typing |
| Agents | `agents.php` | Five agents (prompts, validation, retry) |
| Pipeline | `pipeline.php` | Orchestrator, deterministic findings injection, plugin installation |
| Router | `index.php` | URL dispatch, SSE handler, async worker dispatch |
| Client | `app.js` | Sends credentials, listens on SSE, renders state |
| View | `render.php` | HTML template |
| Auxiliary plugin | `wp-plugin/wpdiag-endpoint.php` | Read-only REST endpoints on the target site |

---

## Agent design

Each agent is a pure function with a single responsibility. It builds a system prompt, sends it to Gemini along with a user message, validates the JSON response, retries once with a corrective instruction if needed.

**Role discipline:** each agent does its own job. The Verifier corrects the Analyzer's output but does NOT introduce new claims. The Writer and Operator do not re-audit the diagnosis.

### Agent 1 — Forensic (pre-analysis)

**Input:** forensic context string (from `forensics.php`).
**Output:** `{risk_level, summary, compromise_indicators, suspicious_files}`.
**Role:** Summarizes facts from the forensic data. Does **not** give recommendations — that is the Operator's job. Distinguishes strong verifications (checksum_mismatch, extra_file, unverifiable_zone) from weak ones (no_checksum, no_checksum_legit_name). Reports clean external scanner results as positive indicators.

### Agent 2 — Analyzer

**Input:** technical context + forensic pre-analysis.
**Output:** `{main_cause, category, confidence, severity, findings, forensic_findings, alternative_hypotheses, missing_info, requires_human, requires_human_reason}`.
**Role:** Produces a unified diagnosis. Must distinguish technical findings from forensic findings. Deterministic findings (WP_DEBUG, WP_CRON, SSL, extensions, core update) are **not** required from the LLM — they are injected by the pipeline. Guided by a severity matrix (critical/high/medium/low/informational) and a hard rule against "tampered/nonexistent" terminology for WordPress versions.

### Agent 3 — Verifier

**Input:** technical context + forensic pre-analysis + Analyzer output.
**Output:** `{verdict, removed_findings, added_findings, severity_corrections, final_diagnosis}`.
**Role:** Audits the Analyzer's diagnosis. It is a **corrector, not a second analyst**: it does not introduce new claims, terminology, or severity without evidence. HARD RULES: cannot escalate severity of `premium_or_custom` findings above `informational`, cannot escalate outdated WordPress core above `medium`, cannot accept "nonexistent" WordPress versions, must reject `recent_changes` as evidence of compromise.

### Agent 4 — Writer

**Input:** verified diagnosis (with `external_scanners` attached if present) + site language code.
**Output:** `{detected_tech_level, response, language}`.
**Role:** Writes the client-ready reply **in the site's language** (passed as a mandatory parameter from the pipeline). Mentions clean external scanner results near the end of the response. Uses defensive terminology (never says "tampered" or "critical" without evidence).

### Agent 5 — Operator

**Input:** verified diagnosis + site URL + site language code.
**Output:** `{actions[]}`.
**Role:** Produces a single prioritized action list. Closed list of allowed UI actions + open `manual_action` fallback. Manual actions are marked with `executable: false`. Must translate action labels to the site's language. Must always include a `generate_report` action at the end.

---

## JSON contract (shared between plugin and interface)

| Field | Where defined | Notes |
|-------|---------------|-------|
| `site.language` | Plugin | ISO code like `es-ES`, `en-US` |
| `wordpress.debug_active` | Plugin | Boolean |
| `wordpress.wp_cron_disabled` | Plugin | Boolean |
| `wordpress.ssl_active` | Plugin | Boolean |
| `server.php_extensions` | Plugin | Array of lowercase strings |
| `updates.core_available` | Plugin | Boolean |
| `updates.pending_plugins` | Plugin | Integer |
| `critical_options.siteurl` / `.home` | Plugin | Strings |
| `scan_stats.files_scanned` etc. | Plugin | Integers (forensics only) |
| `suspicious_files[].origin` | Plugin | `wporg_verified` / `wporg_unverified` / `premium_or_custom` / `custom_mu_plugin` / `suspicious_zone` / `core` |
| `suspicious_files[].verification` | Plugin | `checksum_mismatch` / `extra_file` / `no_checksum` / `no_checksum_legit_name` / `premium_unverifiable` / `wporg_unverifiable` / `unverifiable_zone` |

Every field is expected by the interface in `context.php`, `forensics.php`, and `pipeline.php`. Changing a key requires changing both sides.

---

## Pipeline flow

    run_pipeline(site_url, wpdiag_key, gemini_key, run_id,
                 vt_api_key = '', sucuri_api_key = '')
         │
         ▼
    Step 0: Collect technical context    ← verify_plugin()
         │
         ▼
    Step 1: Forensic pre-analysis         ← fetch_forensics()
         │                                   + vt_scan_url()
         │                                   + sucuri_scan_url()
         │                                   + forensic_agent()
         │
         │  External scanner results are stored in
         │  state.forensics_raw.external_scanners
         │
         ▼
    Step 2: Analyzer                      ← analyzer_agent()
         │
         ├── inject_deterministic_findings()
         │
         └── if confidence=low → STOP (requires_human)
         │
         ▼
    Step 3: Verifier                      ← verifier_agent()
         │
         └── if verdict=rejected → STOP (requires_human)
         │
         ▼
    Step 4: Writer                        ← writer_agent(lang)
         │
         │  Diagnosis + external_scanners attached
         │
         ▼
    Step 5: Operator                      ← operator_agent(lang)
         │
         ├── ensure generate_report present
         │
         ▼
    Completed

**State persistence:** each step writes the full state to a temp file keyed by `run_id`. SSE reads that temp file every 500ms and emits `event: state` when the hash changes.

**Async worker:** `handle_run()` returns a `run_id` and dispatches a fire-and-forget `run_bg` request via curl to the same host. That request runs the full pipeline. Scanner API keys are passed in the POST body of that request.

---

## HTTP contracts

### Interface endpoints (via `index.php?action=...`)

| Action | Method | Input | Output |
|--------|--------|-------|--------|
| `ping` | GET | — | Server diagnostics + Gemini reachability |
| `detect` | POST | `{site_url, gemini_key}` | `{status: installed\|not_installed\|error}` |
| `verify` | POST | `{site_url, gemini_key, wpdiag_key}` | `{status: ok\|error}` |
| `install` | POST | `{site_url, gemini_key, wp_user, wp_password}` | `{status: ok\|error, wpdiag_key?}` |
| `get_key` | POST | `{site_url, gemini_key, wp_user, wp_password}` | `{status: ok\|error, wpdiag_key?}` |
| `run` | POST | `{site_url, gemini_key, wpdiag_key, vt_api_key?, sucuri_api_key?}` | `{status: ok, run_id}` |
| `run_bg` | POST | `{run_id, site_url, wpdiag_key, gemini_key, vt_api_key?, sucuri_api_key?}` | (internal) |
| `state` | GET | `?run_id=X` | Current state JSON |
| `stream` | GET | `?run_id=X` | SSE stream of `state` events |
| `plugin_zip` | GET | — | `wpdiag-endpoint.zip` |
| `download_plugin` | GET | — | `wpdiag-endpoint.php` |

### Auxiliary plugin endpoints (on target site)

| Endpoint | Auth | Response |
|----------|------|----------|
| `/wp-json/wpdiag/v1/status` | Public | `{ok: true, plugin, version}` |
| `/wp-json/wpdiag/v1/context` | `X-WPDiag-Key` | Full technical context |
| `/wp-json/wpdiag/v1/forensics` | `X-WPDiag-Key` | Full forensic data |
| `/wp-json/wpdiag/v1/setup-key` | `manage_options` | `{api_key}` |

---

## External scanners

Scanner API keys are provided per-run by the user (via POST body). They are never read from `config.php` and never stored server-side.

**Result shape** (`vt_scan_url()` and `sucuri_scan_url()` return the same structure):

```php
[
  'status'  => 'ok' | 'partial' | 'error',
  'reason'  => null | 'not_configured' | 'invalid_key' | 'rate_limit'
             | 'timeout' | 'service_down' | 'parse_error'
             | 'submission_failed' | 'incomplete' | 'unknown',
  'message' => string|null,
  'data'    => array|null,
]