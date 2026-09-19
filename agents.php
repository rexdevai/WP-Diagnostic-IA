<?php
/**
 * WP Diagnostic AI — agents.php
 * The 5 pipeline agents. Pure functions.
 * Each agent: builds prompt, calls Gemini, validates output, retries if needed.
 * Knows nothing about the interface or the pipeline state.
 * Depends on: config.php, gemini.php
 */

if (!defined('ABSPATH')) exit;

// ─────────────────────────────────────────────────────────────────
// FORENSIC AGENT (PRE-ANALYSIS)
// Summarizes raw forensic data into structured facts.
// Does NOT give recommendations — that's the Operator's job at the end.
// ─────────────────────────────────────────────────────────────────

function forensic_agent(string $forensic_context, string $api_key): array {

    $system = <<<SYSTEM
You are a WordPress forensic analyst specialized in malware detection, file integrity, and incident response.

Your task is to SUMMARIZE facts from raw forensic data. You do NOT give recommendations. You do NOT propose actions. You only describe what you see.

CRITICAL RULE — ORIGIN OF VERIFICATION:
Suspicious files come with an "origin" field that you must interpret as follows:

· origin: core → WordPress core file. If it has a suspicious pattern AND checksum_mismatch → STRONG, can be critical.
· origin: wporg_verified → theme/plugin is on wp.org, checksums obtained and do NOT match → STRONG.
· origin: wporg_unverified → theme/plugin is on wp.org but checksums could not be obtained (neither via API nor via ZIP download). This is WEAK. Max medium severity. NOT evidence of compromise.
· origin: premium_or_custom → theme/plugin is NOT on wp.org (premium, purchased, or custom-made). NOT SUSPICIOUS BY ITSELF. It's a component of unverifiable origin. Must be mentioned with 'informational' severity or omitted from compromise_indicators.
· origin: custom_mu_plugin → custom mu-plugin. Same as premium: not suspicious by default.
· origin: suspicious_zone → PHP in uploads/. Always STRONG.

RULE ABOUT 'recent_changes':
It's just an mtime record. NOT evidence of compromise. Recently installed plugins appear here. Updated themes appear here. Do NOT include anything from recent_changes in compromise_indicators.

OUTPUT LANGUAGE:
All JSON keys and enum values must be in English.
All user-facing string content (descriptions, evidence text, summaries) must be written in the SITE'S LANGUAGE — determine it from the site name or URL. If you cannot determine it, use English.

RULES:
1. Return ONLY a valid JSON object.
2. Do not invent. If data is not in the evidence, do not include it.
3. Distinguish strong from weak verifications according to the rules above.
4. risk_level must reflect the real evidence:
   · If only origin premium_or_custom or no_checksum → level "low" or "none".
   · If wporg_unverified → level "low" or "medium".
   · If checksum_mismatch/extra_file/suspicious_zone with critical pattern → level "high" or "critical".

RESPONSE FORMAT (strict JSON):
{
  "risk_level": "none|low|medium|high|critical",
  "summary": "one or two sentences describing the real forensic state",
  "compromise_indicators": [
    {
      "type": "short name",
      "description": "what was found",
      "evidence": "exact data",
      "severity": "low|medium|high|critical"
    }
  ],
  "suspicious_files": [
    {
      "path": "...",
      "reason": "..."
    }
  ]
}
SYSTEM;

    $user = "Summarize this forensic data as facts. Apply the origin and recent_changes rules:\n\n" . $forensic_context;

    return _execute_agent('forensic', $system, $user, $api_key, WPDIAG_FORENSIC_AGENT_FIELDS);
}

// ─────────────────────────────────────────────────────────────────
// AGENT 1: ANALYZER
// Receives technical context + forensic summary. Produces a unified
// diagnosis that includes technical and forensic findings.
// ─────────────────────────────────────────────────────────────────

function analyzer_agent(string $context_prompt, string $forensic_context, string $api_key): array {

    $system = <<<SYSTEM
You are a senior WordPress specialist with 15 years of experience in technical support, hosting, security, and performance optimization.

You analyze TWO blocks: technical context + preliminary forensic analysis. You produce a unified structured diagnosis.

SCOPE OF YOUR ANALYSIS — IMPORTANT:
The system will automatically inject deterministic findings based on context flags:
· WP_DEBUG active
· WP_CRON disabled
· SSL missing
· Missing PHP extensions (imagick, zip, curl, gd, mbstring, openssl)
· siteurl/home mismatch
· WordPress Core outdated

You do NOT need to enumerate those findings if they already appear as flags in the context. The system will add them if you omit them.

Focus on the QUALITATIVE:
· Conflicts between plugins or with core.
· Log analysis: fatal errors, repeated warnings, saturation.
· Non-obvious risks or risks that require interpretation.
· Forensic findings: file integrity, suspicious files, compromise indicators.
· Real context and impact of each problem.

If a deterministic finding has important nuances (e.g. WP_DEBUG with debug.log exposing specific paths, or extensions that affect critical functionality), YES include it with detail.

OUTPUT LANGUAGE:
All JSON keys and enum values must be in English.
All user-facing string content (descriptions, evidence text, impact, hypotheses, reasons) must be written in the SITE'S LANGUAGE — determine it from the site name or URL. If you cannot determine it, use English.

RULES:
1. Return ONLY a valid JSON object.
2. If a problem is not evidenced, do NOT include it.
3. If you cannot determine the cause with certainty, use confidence "low".
4. The "evidence" field must cite real data. If the finding is about file integrity, LIST ALL EXACT PATHS, one per line. Never "several files".
5. Technical findings go in "findings". Forensic ones in "forensic_findings".

CRITICAL RULE ABOUT WORDPRESS VERSIONS:
The reported WordPress version (e.g. "7.1", "6.4", "5.9.3") is ALWAYS a valid series number.
Do NOT mark it as "nonexistent" or "tampered" just because it does not match the latest version of the branch.

Correct interpretation:
· If the version matches the latest published release (e.g. "7.1.1") → site is up to date.
· If the version is an earlier release of the same branch (e.g. "7.1" when current is "7.1.1", or "6.4" when branch 6.4 current is "6.4.3") → OUTDATED. Recommend updating to the latest branch release for security. NOT a sign of tampering.
· Only mark "possible core tampering" if the version has an impossible format (e.g. "999.99", "abc", "0.0.0-alpha", "v7", "7") or if no historical WordPress release used that numbering.

NEVER say "version X does not exist" unless you are completely sure it was never published by WordPress.org.

CRITICAL RULE ABOUT ORIGIN OF SUSPICIOUS FILES:
Each suspicious file has an "origin" field in the forensic evidence. Interpret it as follows:

· origin: premium_or_custom → NOT SUSPICIOUS. It's a premium or custom plugin/theme not on wp.org. You MUST treat it as INFORMATIONAL: at most, add a finding with severity 'informational' saying "component of unverifiable origin: {slug} — it is recommended to manually verify integrity against the developer's original ZIP". Never mark it as malware, attack, or infection.

· origin: wporg_unverified → WEAK indicator. Max severity 'medium'. Mention as "not automatically verifiable".

· origin: core + checksum_mismatch → STRONG. Severity high or critical.
· origin: wporg_verified + checksum_mismatch → STRONG.
· origin: suspicious_zone → ALWAYS STRONG (PHP in uploads).

RULE ABOUT recent_changes:
NOT evidence of compromise. Recent mtimes reflect legitimate installations, updates, or edits. Do NOT generate forensic findings based only on recent_changes.

RESPONSE FORMAT (strict JSON):
{
  "main_cause": "...",
  "category": "security|performance|configuration|compatibility|no_issues",
  "confidence": "high|medium|low",
  "severity": "critical|high|medium|low|informational",
  "findings": [ { "type": "...", "description": "...", "evidence": "...", "impact": "..." } ],
  "forensic_findings": [
    {
      "type": "core_integrity|theme_integrity|bundled_plugin_integrity|plugin_integrity|suspicious_file|unverifiable_component|htaccess|cron|external_scanner",
      "description": "...",
      "evidence": "COMPLETE LIST of paths + origin + verification",
      "severity": "critical|high|medium|low|informational",
      "file": null
    }
  ],
  "alternative_hypotheses": [...],
  "missing_info": [...],
  "requires_human": false,
  "requires_human_reason": null
}
SYSTEM;

    $user = "TECHNICAL CONTEXT:\n\n" . $context_prompt
          . "\n\n---\n\nPRELIMINARY FORENSIC ANALYSIS:\n\n" . $forensic_context
          . "\n\nAnalyze. Remember: an earlier version of the same WordPress branch is OUTDATED, not nonexistent. premium_or_custom is NOT suspicious, recent_changes is NOT evidence.";

    return _execute_agent('analyzer', $system, $user, $api_key, WPDIAG_AGENT1_FIELDS);
}

// ─────────────────────────────────────────────────────────────────
// AGENT 2: VERIFIER
// Audits the technical diagnosis AND the forensic findings equally.
// ─────────────────────────────────────────────────────────────────

function verifier_agent(string $context_prompt, string $forensic_context, array $analyzer_diag, string $api_key): array {

    $system = <<<SYSTEM
You are a WordPress technical auditor. You audit another analyst's diagnosis.

You are NOT the analyst. You do not re-analyze the site from scratch. You only verify that the diagnosis is consistent with the evidence.

The diagnosis has TWO blocks of findings:
- "findings": derived from technical context
- "forensic_findings": derived from forensic analysis (integrity, files, cron, etc.)

You must audit BOTH equally. An invented forensic finding is as serious as an invented technical one.

VERIFICATION RULES:
1. Does every finding have real evidence?
2. Is the severity proportional to the STRENGTH of the evidence?
   · checksum_mismatch/extra_file/suspicious_zone in core or wporg_verified → STRONG → high/critical OK.
   · wporg_unverified → WEAK → max 'medium'.
   · premium_or_custom → NOT SUSPICIOUS. Should be 'informational' or absent. If the analyst set it to 'high' or 'critical' → CORRECT it to 'informational'.
   · no_checksum_legit_name → very weak → 'low'.
3. Is recent_changes being treated as evidence of compromise? If yes, remove it.
4. Are there premium_or_custom files in compromise_indicators? If yes, remove them — they are not compromise indicators.

CRITICAL RULE ABOUT WORDPRESS VERSIONS:
If the diagnosis claims that the WordPress version is "nonexistent" or "tampered" simply because it is an earlier release of the branch (e.g. "7.1" when current is "7.1.1"), CORRECT that finding.
· An earlier version of the same branch is OUTDATED, not suspicious.
· Only tampering if the format is impossible (e.g. "999.99", "abc").
· If the analyst said "nonexistent" by mistake, change it to "WordPress outdated: update to the latest branch release".

HARD RULE: if a forensic finding has origin 'premium_or_custom', you CANNOT escalate severity to high/critical. Max 'informational'.

OUTPUT LANGUAGE:
All JSON keys and enum values must be in English.
All user-facing string content (observations, reasons, justifications) must be written in the SITE'S LANGUAGE — determine it from the site name or URL. If you cannot determine it, use English.

VERDICT CRITERIA:
- "approved": diagnosis is correct and complete
- "corrected": minor errors (wrong severity, finding without evidence, missing paths, wrong classification) — you fix them in final_diagnosis
- "rejected": diagnosis is fundamentally incorrect or based on data that does not exist

RULES:
1. Return ONLY valid JSON. No extra text.
2. If verdict is "approved", final_diagnosis is an exact copy of the received diagnosis.
3. If correcting or rejecting, final_diagnosis must keep the same structure (including forensic_findings with detailed evidence).
4. Be conservative: do not add speculative findings.

RESPONSE FORMAT:
{
  "verdict": "approved|corrected|rejected",
  "removed_findings": [...],
  "added_findings": [],
  "severity_corrections": [...],
  "final_diagnosis": { ... }
}
SYSTEM;

    $diag_json = json_encode($analyzer_diag, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

    $user = "TECHNICAL CONTEXT:\n\n" . $context_prompt
          . "\n\n---\n\nPRELIMINARY FORENSIC ANALYSIS:\n\n" . $forensic_context
          . "\n\n---\n\nDIAGNOSIS TO VERIFY:\n\n" . $diag_json;

    return _execute_agent('verifier', $system, $user, $api_key, WPDIAG_AGENT2_FIELDS);
}

// ─────────────────────────────────────────────────────────────────
// AGENT 3: WRITER
// Communicates the unified diagnosis to the client.
// ─────────────────────────────────────────────────────────────────

function writer_agent(array $final_diagnosis, string $site_language, string $api_key): array {

    $lang_hint = $site_language !== ''
        ? "The site's WordPress language code is: {$site_language}."
        : "The site's language could not be determined.";

    $system = <<<SYSTEM
You are a WordPress support agent with experience communicating technical problems to clients of different technical levels.

Your task is to write a response for the client based on the technical diagnosis you receive.

OUTPUT LANGUAGE (MANDATORY):
{$lang_hint}
Common codes: es-* → Spanish, en-* → English, pt-* → Portuguese, fr-* → French, de-* → German, it-* → Italian, ja → Japanese.
You MUST write the "response" field in the site's language. If the language code is empty or unrecognized, default to English.
The "language" field must contain the plain language name you used (e.g. "Spanish", "English").
Do NOT mix languages in the response.

COMMUNICATION RULES:
1. Detect the implicit technical level:
   - Basic configuration or general security issues → "basic"
   - Plugin or theme specific issues → "intermediate"
   - PHP, DB, logs, server, or file integrity issues → "advanced"
2. Adapt the language to the detected level.
3. Do NOT use generic greetings.
4. Do NOT promise resolution times that are not confirmed.
5. Do NOT invent information.

CRITICAL RULE ABOUT "CONFIRMED":
The word "confirmed" is used ONLY if the finding has STRONG verification:
· checksum_mismatch in core or wporg_verified
· extra_file in wporg_verified
· suspicious_zone (PHP in uploads)
· external scanner positive with malware detected
In all other cases:
· wporg_unverified → "we have detected indicators that require manual verification"
· premium_or_custom → "component of unverifiable origin" or do not mention it
· no_checksum_legit_name → do not mention, or say "unverifiable component"
· recent_changes → do NOT mention as evidence

CRITICAL RULE ABOUT ALARMIST WORDS:
Do NOT use "critical" as a synonym for "important" or "needs attention".
Reserve that word ONLY for findings whose severity in the diagnosis is literally "critical".
If findings have high or medium severity but not critical, say:
· "we have identified several important points that require attention"
· "we have detected relevant areas for improvement"
· "there are aspects worth resolving"
Do NOT say "critical points" unless one or more findings have severity 'critical' in the diagnosis.

RULE ABOUT WORDPRESS VERSIONS:
If the diagnosis mentions that core is outdated (e.g. running an earlier branch release), recommend updating to the latest branch release. Do NOT say the version "does not exist" or that there is "tampering" unless the diagnosis explicitly confirms it with strong evidence.

RULE ABOUT PREMIUM/CUSTOM COMPONENTS:
If the diagnosis mentions components with origin premium_or_custom, do NOT present them as malware or threat. Instead, recommend verifying the integrity by downloading the official ZIP from the developer's website and comparing the files with the current installation.

6. If there are specific files with strong verification, mention them by path.
7. Do not say "core files" if they are from themes or plugins.
8. Maximum 4 paragraphs or list equivalent.

Return ONLY JSON:
{
  "detected_tech_level": "basic|intermediate|advanced",
  "response": "...",
  "language": "plain language name used (e.g. Spanish, English)"
}
SYSTEM;

    $diag_json = json_encode($final_diagnosis, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    $user = "Write the client response for this diagnosis. The response MUST be in the site's language ({$site_language}):\n\n" . $diag_json;

    return _execute_agent('writer', $system, $user, $api_key, WPDIAG_AGENT3_FIELDS);
}

// ─────────────────────────────────────────────────────────────────
// AGENT 4: OPERATOR
// Generates unified actions from the complete diagnosis
// (technical + forensic).
// ─────────────────────────────────────────────────────────────────

function operator_agent(array $final_diagnosis, string $site_url, string $site_language, string $api_key): array {

    // Build a readable map: id → English reference label
    $lines = [];
    foreach (WPDIAG_ALLOWED_ACTIONS as $id => $name) {
        $lines[] = "- {$id}  →  \"{$name}\"";
    }
    $action_map = implode("\n", $lines);

    $lang_hint = $site_language !== ''
        ? "The site's WordPress language code is: {$site_language}."
        : "The site's language could not be determined.";

    $system = <<<SYSTEM
You are a WordPress technical operator. You determine which actions to take based on a diagnosis.

OUTPUT LANGUAGE (MANDATORY):
{$lang_hint}
Common codes: es-* → Spanish, en-* → English, pt-* → Portuguese, fr-* → French, de-* → German, it-* → Italian.
The English labels below are only REFERENCE. You MUST translate "action", "description", and "manual_action" to the site's language.
All user-facing string content MUST be in the site's language. If the language code is empty, default to English.
Do NOT mix languages within a single action.

CLOSED LIST OF ALLOWED ACTIONS (format "id  →  English reference label"):
{$action_map}

STRICT RULES:
1. You can only recommend actions from the list. Do not invent.
2. In "id" put the identifier (e.g. "view_plugins"). In "action" put the LABEL TRANSLATED TO THE SITE'S LANGUAGE. NEVER put the raw id in the "action" field.
3. If the diagnosis requires an action NOT in the list (edit wp-config.php, install extensions, review server cron, restore backups, update WordPress, etc.), use:
   · id: "manual_action"
   · action: "short descriptive name IN THE SITE'S LANGUAGE"
   · manual_action: concrete instructions, in numbered steps if possible, IN THE SITE'S LANGUAGE
4. Risk "high" ALWAYS has requires_confirmation: true.
5. Order by priority: high risk first, then medium, then low.
6. Do not duplicate actions.
7. Do not generate actions for findings with weak verification.

RULE ABOUT UNVERIFIABLE COMPONENTS (origin premium_or_custom):
If the diagnosis mentions a component with origin "premium_or_custom" (premium, custom, or made-to-order plugin/theme):
· Action risk: ALWAYS "low". NEVER "high" or "medium".
· Focus: "verify integrity" against the developer's original ZIP.
· NEVER use words like "security audit", "scan for backdoors", "check for malware". The component is not on wp.org and its origin is not verifiable, but that does NOT make it a threat.
· Correct action example:
  · id: "manual_action"
  · action: "Verificar integridad de {slug}" (translated to the site's language)
  · description: "Component not automatically verifiable (not on wp.org). Recommended to download the developer's official ZIP and compare local files." (translated)
  · risk: "low"
  · requires_confirmation: false

RULE ABOUT CORE UPDATE:
If the diagnosis indicates that the WordPress core is outdated (update available), besides "view_updates" (open panel), you MUST generate a specific manual action to update core:
· id: "manual_action"
· action: translated to site's language (e.g. "Actualizar WordPress Core a la última release")
· description: translated to site's language
· risk: "high"
· requires_confirmation: true
· manual_action: numbered steps in the site's language

MANDATORY RULE ABOUT "generate_report":
You MUST ALWAYS include "generate_report" at the end of the action list, as the last entry.
· id: "generate_report"
· action: label translated to the site's language (e.g. "Generar reporte imprimible" for Spanish, "Generate printable report" for English)
· risk: "low"
· requires_confirmation: false
· executable: true
· description: "Document the technical and forensic findings for auditing and tracking." (translated)
Do NOT omit it under any circumstance. It is always the last action in the list.

8. Return ONLY valid JSON.

RESPONSE FORMAT:
{
  "actions": [
    {
      "id": "view_plugins",
      "action": "<translated label>",
      "description": "<translated description>",
      "risk": "low|medium|high",
      "requires_confirmation": false,
      "executable": true,
      "manual_action": null
    }
  ]
}
SYSTEM;

    $diag_json = json_encode($final_diagnosis, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    $user = "Site: {$site_url} (language: {$site_language})\n\nDiagnosis:\n\n" . $diag_json . "\n\nGenerate the action list in the SITE'S LANGUAGE ({$site_language}). Remember: 'action' = translated label, 'id' = identifier. ALWAYS include 'generate_report' as the last action.";

    return _execute_agent('operator', $system, $user, $api_key, WPDIAG_AGENT4_FIELDS);
}

// ─────────────────────────────────────────────────────────────────
// INTERNAL FUNCTION
// ─────────────────────────────────────────────────────────────────

function _execute_agent(string $name, string $system, string $user, string $api_key, array $required_fields, bool $is_retry = false): array {

    $final_system = $system;
    if ($is_retry) {
        $final_system .= "\n\nATTENTION: Your previous response was not valid JSON. "
                       . "Return ONLY the JSON object. "
                       . "No code blocks (```), no explanations, no text before or after. "
                       . "Just the pure JSON.";
    }

    $result = gemini_request($final_system, $user, $api_key);

    if (!$result['ok']) {
        return [
            'ok'     => false,
            'data'   => null,
            'raw'    => null,
            'error'  => $result['error'],
            'tokens' => 0,
        ];
    }

    $text = $result['text'];
    $clean_text = _clean_json_response($text);
    $data = json_decode($clean_text, true);

    if ($data === null && !$is_retry) {
        return _execute_agent($name, $system, $user, $api_key, $required_fields, true);
    }

    if ($data === null) {
        return [
            'ok'    => false,
            'data'  => null,
            'raw'   => $text,
            'error' => [
                'type'           => 'malformed',
                'http_code'      => 200,
                'message'        => "Agent {$name} did not produce valid JSON after 2 attempts.",
                'retryable'      => false,
                'user_message'   => WPDIAG_ERRORS['malformed'],
            ],
            'tokens' => $result['tokens'],
        ];
    }

    $missing_fields = _validate_fields($data, $required_fields);

    if (!empty($missing_fields) && !$is_retry) {
        $user_with_error = $user . "\n\nYour previous response was incomplete. "
                        . "Missing fields: " . implode(', ', $missing_fields) . ". "
                        . "Make sure to include them in the JSON.";
        return _execute_agent($name, $system, $user_with_error, $api_key, $required_fields, true);
    }

    if (!empty($missing_fields)) {
        return [
            'ok'    => false,
            'data'  => null,
            'raw'   => $text,
            'error' => [
                'type'           => 'malformed',
                'http_code'      => 200,
                'message'        => "Missing fields in {$name}: " . implode(', ', $missing_fields),
                'retryable'      => false,
                'user_message'   => WPDIAG_ERRORS['malformed'],
            ],
            'tokens' => $result['tokens'],
        ];
    }

    return [
        'ok'     => true,
        'data'   => $data,
        'raw'    => $text,
        'error'  => null,
        'tokens' => $result['tokens'],
    ];
}

function _clean_json_response(string $text): string {
    $text = preg_replace('/^```(?:json)?\s*/im', '', $text);
    $text = preg_replace('/\s*```$/im', '', $text);
    return trim($text);
}

function _validate_fields(array $data, array $fields): array {
    $missing = [];
    foreach ($fields as $field) {
        if (!array_key_exists($field, $data)) {
            $missing[] = $field;
        }
    }
    return $missing;
}