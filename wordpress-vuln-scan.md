# WordPress Plugin Vulnerability Scanner

## Trigger
Trigger this skill when the user asks to:
- Scan WordPress plugins for vulnerabilities
- Audit WordPress plugins for security issues
- Find exploitable bugs in WordPress plugins
- Research WordPress plugin security

---

## Overview

This skill fetches recently-updated, high-popularity WordPress plugins from the official WordPress.org API, downloads and analyzes their **full source code** using LLM-based reasoning (not pattern matching), and produces per-plugin HTML vulnerability reports with reproduction steps, impact, and mitigation guidance.

---

## Step 1 — Fetch Plugin List from WordPress.org API

Use the official WordPress.org Plugins API to retrieve plugins sorted by **recently updated** and filtered by **high install/star count**.

```
GET https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[browse]=updated&request[per_page]=50&request[fields][versions]=false&request[fields][ratings]=true&request[fields][active_installs]=true&request[fields][last_updated]=true
```

Also fetch by `browse=popular` to capture high-install-count plugins:
```
GET https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[browse]=popular&request[per_page]=50&request[fields][ratings]=true&request[fields][active_installs]=true&request[fields][last_updated]=true
```

**Merge both lists**, deduplicate by `slug`, and sort by a combined score:
```
score = (active_installs * 0.6) + (rating * 0.4 * 10000)
```
prioritizing plugins that are **both popular AND recently updated**.

**Skip any plugin already listed in `done.txt`** (one slug per line).

---

## Step 2 — Download Plugin Source Code

For each plugin in the list, download the latest zip from the official SVN/download endpoint:

```
https://downloads.wordpress.org/plugin/{slug}.latest-stable.zip
```

Extract the zip to a temp directory. You now have the **full plugin source tree**.

Do NOT limit analysis to changelogs or diff patches — analyze all `.php`, `.js`, `.twig`, `.html` files in the extracted directory.

---

## Step 3 — LLM-Based Vulnerability Analysis

> **Critical**: Do NOT use regex or pattern matching as the primary detection method. Use Claude to reason over the code semantically.

Feed the plugin's source files to Claude in batches (by file or logical module) with the following analysis prompt per file/module:

### Analysis Prompt Template

```
You are a senior application security researcher auditing a WordPress plugin for exploitable vulnerabilities.

Plugin: {plugin_name} v{version}
File: {relative_file_path}

Analyze the following source code for security vulnerabilities that could be exploited by an **end user** (authenticated or unauthenticated visitor) of a WordPress site running this plugin.

Focus ONLY on vulnerabilities that are:
- Exploitable from the outside (front-end, REST API, AJAX handlers, shortcodes, form submissions, file uploads, redirects)
- Not requiring server or database access to trigger
- Realistic — not theoretical or requiring extreme preconditions

Vulnerability classes to check (non-exhaustive):
- SQL Injection (direct or second-order)
- Cross-Site Scripting (Reflected, Stored, DOM)
- CSRF (missing nonce checks on state-changing actions)
- Insecure Direct Object Reference (IDOR)
- Arbitrary File Upload / Path Traversal
- Unauthenticated privilege escalation
- Remote Code Execution via user-controlled input
- Insecure deserialization
- Open Redirect
- Sensitive data exposure via AJAX/REST endpoints

For each confirmed or highly probable vulnerability, output a JSON object:
{
  "title": "Short vulnerability title",
  "type": "Vulnerability class (e.g. Stored XSS, SQLi, CSRF)",
  "file": "relative/path/to/file.php",
  "line_start": <line number>,
  "line_end": <line number>,
  "vulnerable_code_snippet": "exact snippet from source",
  "summary": "Plain-English explanation of the vulnerability",
  "exploitability": "High | Medium | Low",
  "authentication_required": "None | Subscriber | Contributor | Editor | Admin",
  "steps_to_reproduce": [
    "Step 1...",
    "Step 2...",
    "Step 3..."
  ],
  "impact": "Description of what an attacker can achieve",
  "mitigation": "Specific code fix or hardening recommendation",
  "cvss_estimate": "CVSS v3 base score estimate (e.g. 8.1)"
}

If no exploitable vulnerability exists in this file, output: []

Source code:
\`\`\`
{source_code}
\`\`\`
```

Collect all JSON finding objects across all files for the plugin.

---

## Step 4 — Generate HTML Report

For each plugin that has at least one finding, generate `{plugin_slug}.html` in the output directory using the following structure:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Vulnerability Report — {Plugin Name}</title>
  <style>
    /* --- Reset & Base --- */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #e2e8f0; line-height: 1.6; }
    a { color: #60a5fa; }

    /* --- Header --- */
    .header { background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%); padding: 40px 60px; border-bottom: 1px solid #334155; }
    .header h1 { font-size: 2rem; font-weight: 700; color: #f8fafc; }
    .header .meta { margin-top: 10px; font-size: 0.9rem; color: #94a3b8; }
    .badge { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 0.75rem; font-weight: 600; margin-left: 8px; }
    .badge-critical { background: #7f1d1d; color: #fca5a5; }
    .badge-high { background: #7c2d12; color: #fdba74; }
    .badge-medium { background: #713f12; color: #fde68a; }
    .badge-low { background: #14532d; color: #86efac; }

    /* --- Summary Bar --- */
    .summary-bar { display: flex; gap: 20px; padding: 24px 60px; background: #161b27; border-bottom: 1px solid #1e293b; flex-wrap: wrap; }
    .stat { background: #1e293b; border-radius: 8px; padding: 16px 24px; min-width: 120px; }
    .stat .label { font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
    .stat .value { font-size: 1.8rem; font-weight: 700; color: #f8fafc; }

    /* --- Content --- */
    .content { padding: 40px 60px; max-width: 1400px; }
    .section-title { font-size: 1.2rem; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.08em; margin: 40px 0 20px; border-bottom: 1px solid #1e293b; padding-bottom: 10px; }

    /* --- Finding Card --- */
    .finding { background: #1a1f2e; border: 1px solid #1e293b; border-radius: 12px; margin-bottom: 28px; overflow: hidden; }
    .finding-header { display: flex; justify-content: space-between; align-items: center; padding: 18px 24px; background: #161b27; border-bottom: 1px solid #1e293b; cursor: pointer; }
    .finding-header h3 { font-size: 1rem; font-weight: 600; color: #f1f5f9; }
    .finding-body { padding: 24px; }
    .finding-meta { display: flex; gap: 24px; margin-bottom: 20px; flex-wrap: wrap; font-size: 0.85rem; color: #64748b; }
    .finding-meta span strong { color: #94a3b8; }

    /* --- Code Block --- */
    .code-block { background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 16px; overflow-x: auto; margin: 12px 0; }
    .code-block pre { font-family: 'Fira Code', 'Cascadia Code', monospace; font-size: 0.82rem; color: #c9d1d9; white-space: pre; }
    .code-location { font-size: 0.75rem; color: #6366f1; margin-bottom: 6px; font-family: monospace; }

    /* --- Steps --- */
    ol.steps { padding-left: 22px; margin: 10px 0; }
    ol.steps li { margin-bottom: 6px; color: #cbd5e1; font-size: 0.9rem; }

    /* --- Impact / Mitigation --- */
    .impact-box { background: #1c1917; border-left: 3px solid #ef4444; border-radius: 0 8px 8px 0; padding: 12px 16px; margin: 12px 0; font-size: 0.9rem; color: #fca5a5; }
    .mitigation-box { background: #052e16; border-left: 3px solid #22c55e; border-radius: 0 8px 8px 0; padding: 12px 16px; margin: 12px 0; font-size: 0.9rem; color: #86efac; }
    .label-row { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 700; margin-bottom: 6px; }

    /* --- Footer --- */
    .footer { padding: 30px 60px; color: #475569; font-size: 0.8rem; border-top: 1px solid #1e293b; margin-top: 40px; }
  </style>
</head>
<body>

<div class="header">
  <h1>{Plugin Name} — Security Report</h1>
  <div class="meta">
    Plugin Slug: <strong>{plugin_slug}</strong> &nbsp;|&nbsp;
    Version Scanned: <strong>{version}</strong> &nbsp;|&nbsp;
    Active Installs: <strong>{active_installs}+</strong> &nbsp;|&nbsp;
    Last Updated: <strong>{last_updated}</strong> &nbsp;|&nbsp;
    Scan Date: <strong>{scan_date}</strong>
  </div>
</div>

<div class="summary-bar">
  <div class="stat"><div class="label">Total Findings</div><div class="value">{total_count}</div></div>
  <div class="stat"><div class="label">High / Critical</div><div class="value" style="color:#f87171">{high_count}</div></div>
  <div class="stat"><div class="label">Medium</div><div class="value" style="color:#fbbf24">{medium_count}</div></div>
  <div class="stat"><div class="label">Low</div><div class="value" style="color:#4ade80">{low_count}</div></div>
  <div class="stat"><div class="label">Files Scanned</div><div class="value">{files_scanned}</div></div>
</div>

<div class="content">

  <div class="section-title">Findings</div>

  <!-- Repeat for each finding -->
  <div class="finding">
    <div class="finding-header">
      <h3>{finding.title}</h3>
      <span class="badge badge-{severity_class}">{finding.exploitability} — {finding.type}</span>
    </div>
    <div class="finding-body">

      <div class="finding-meta">
        <span><strong>Auth Required:</strong> {finding.authentication_required}</span>
        <span><strong>CVSS Estimate:</strong> {finding.cvss_estimate}</span>
        <span><strong>Type:</strong> {finding.type}</span>
      </div>

      <p style="color:#cbd5e1; margin-bottom:16px">{finding.summary}</p>

      <div class="code-location">Source: {finding.file} — Lines {finding.line_start}–{finding.line_end}</div>
      <div class="code-block"><pre>{finding.vulnerable_code_snippet}</pre></div>

      <div class="label-row" style="color:#94a3b8; margin-top:20px">Steps to Reproduce</div>
      <ol class="steps">
        <!-- repeat per step -->
        <li>{step}</li>
      </ol>

      <div class="label-row impact-box" style="margin-top:16px">
        <div class="label-row">Impact</div>
        {finding.impact}
      </div>

      <div class="mitigation-box">
        <div class="label-row">Mitigation</div>
        {finding.mitigation}
      </div>

    </div>
  </div>
  <!-- end finding -->

</div>

<div class="footer">
  Generated by Claude Security Scanner &nbsp;|&nbsp; WordPress Plugin: {plugin_slug} &nbsp;|&nbsp; {scan_date}
  <br>This report is for authorized security research only. Responsible disclosure applies.
</div>

</body>
</html>
```

Save the file as `reports/{plugin_slug}.html`.

If no findings exist for a plugin, still save a minimal report noting "No exploitable vulnerabilities found" so scans aren't repeated unnecessarily.

---

## Step 5 — Update done.txt

After scanning a plugin (regardless of findings), append its slug to `done.txt`:

```
# Format: one slug per line
contact-form-7
woocommerce
jetpack
```

Before scanning any plugin, always read `done.txt` and skip slugs already present.

---

## Step 6 — Console Output Per Plugin

Print a summary to the terminal after each plugin scan:

```
[DONE] {plugin_slug} v{version}
  Files scanned : {n}
  Findings      : {total} ({high} high, {medium} medium, {low} low)
  Report        : reports/{plugin_slug}.html
```

---

## Implementation Notes

### Tool Usage
- Use `WebFetch` to call the WordPress.org API endpoints and download plugin zips
- Use `Bash` to unzip archives, list files, and read source
- Use `Read` to load individual source files for LLM analysis
- Use `Write` to produce HTML reports and update `done.txt`
- Use Claude itself (via prompt above) to analyze each file — do NOT use regex-only matching

### File Prioritization (within a plugin)
Analyze in this order of priority:
1. Files registering AJAX handlers (`wp_ajax_`, `wp_ajax_nopriv_`)
2. Files with REST API route registrations (`register_rest_route`)
3. Files processing `$_GET`, `$_POST`, `$_REQUEST`, `$_FILES`, `$_COOKIE`
4. Shortcode handlers (`add_shortcode`)
5. All remaining `.php` files
6. Frontend `.js` files (for DOM XSS, client-side logic)

### Chunking Long Files
If a file exceeds ~500 lines, split it into overlapping chunks of 400 lines (50-line overlap) and analyze each chunk separately, then deduplicate findings by `(file, line_start)`.

### Rate Limiting
Add a 1-second delay between WordPress.org API calls. Do not hammer the download endpoint.

### Output Directory Structure
```
reports/
  {plugin_slug}.html
  ...
done.txt
```

---

## Security & Ethics Constraints

- This skill is for **authorized security research and responsible disclosure only**
- Do NOT attempt to actively exploit discovered vulnerabilities against live sites
- Findings should be reported to the plugin author via the WordPress.org support forum or security@wordpress.org before public disclosure
- Do NOT scan plugins you do not have authorization to test in a live environment
- This skill analyzes **source code only** — no active probing of any server

---

## Example Invocation

User prompt examples that trigger this skill:
- "Scan the latest WordPress plugins for vulnerabilities"
- "Find security issues in recently updated WordPress plugins"
- "Run a WordPress plugin audit"
- "Check popular WordPress plugins for exploitable bugs"
