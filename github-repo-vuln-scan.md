# GitHub Repository Vulnerability Scanner

## Trigger
Trigger this skill when the user asks to:
- Scan a GitHub repository for vulnerabilities
- Audit a GitHub repo for security issues
- Find exploitable bugs in a GitHub project
- Security review a codebase from GitHub
- Check a repo for dependency confusion

---

## Overview

This skill clones a GitHub repository locally, performs full LLM-based source code analysis across all files for exploitable vulnerabilities (not theoretical, not pattern-matched), checks for dependency confusion weaknesses, conducts an exploitability analysis on every finding, and produces a single polished HTML report.

---

## Step 1 — Clone the Repository

```bash
git clone --depth=1 https://github.com/{owner}/{repo}.git /tmp/scan_{repo}
```

If the repo is private, use the token the user provides:
```bash
git clone --depth=1 https://{token}@github.com/{owner}/{repo}.git /tmp/scan_{repo}
```

Record:
- Repo name, default branch, last commit SHA, commit date
- Primary language(s) — use `linguist` or file extension frequency
- Total file count

---

## Step 2 — Build the File Scan Queue

Walk the entire repository tree. Collect **all** files that can contain exploitable logic. Do NOT skip files based on extension alone if the content looks like code.

**Priority order for analysis (analyze in this sequence):**

| Priority | File Types / Patterns | Reason |
|---|---|---|
| P0 | Files handling HTTP requests (routes, controllers, handlers, views) | Direct user-input entry points |
| P1 | Auth & session files (`auth`, `login`, `session`, `token`, `middleware`, `guard`) | Auth bypass surface |
| P2 | Files making outbound HTTP calls (`fetch`, `axios`, `requests`, `curl`, `http.get`) | SSRF surface |
| P3 | Files doing DB queries / ORM calls | SQLi / mass assignment |
| P4 | Files handling file upload, path operations, `eval`, `exec`, template rendering | RCE / traversal |
| P5 | All remaining source files (`.js`, `.ts`, `.py`, `.rb`, `.go`, `.java`, `.php`, `.cs`, `.rs`, `.kt`, `.swift`, `.c`, `.cpp`, `.ex`, `.exs`, `.scala`) | Full coverage |
| P6 | Config files (`.env.example`, `*.yaml`, `*.json`, `*.toml`, `*.ini`, `Dockerfile`, CI configs) | Secrets, misconfig |
| P7 | Frontend files (`.html`, `.jsx`, `.tsx`, `.vue`, `.svelte`, `.ejs`, `.hbs`) | XSS surface |

**Skip:** `node_modules/`, `vendor/`, `.git/`, `dist/`, `build/`, binary files, images, fonts, lockfiles.

---

## Step 3 — LLM-Based Vulnerability Analysis

> **Hard rule**: Use Claude to reason about what the code actually does. Do NOT flag issues based solely on the presence of a function name or string. Trace data flow from source to sink. Assess whether exploitation is realistic.

### Per-file analysis prompt

```
You are a principal security engineer performing a thorough manual code review of a real production codebase. Your job is to find vulnerabilities that are actually exploitable by an external attacker — not theoretical weaknesses, not missing best-practices, not defense-in-depth issues.

Repository: {repo_name}
File: {relative_file_path}
Language: {language}

Rules:
1. Only report a finding if you can trace a clear data flow from an attacker-controlled input to a dangerous outcome.
2. Consider the realistic attacker model: unauthenticated external user, or authenticated user with the lowest available privilege level.
3. Assess exploitability honestly. If a finding requires chaining multiple unlikely conditions, mark exploitability as Low and explain why.
4. Do NOT flag issues that require server-level access or out-of-band knowledge the attacker cannot obtain.
5. Cover ALL vulnerability classes — do not limit yourself to OWASP Top 10. This includes but is not limited to:
   - Injection: SQLi, NoSQLi, LDAP, XPath, OS command, SSTI, Log injection
   - XSS: Stored, Reflected, DOM-based
   - SSRF (including blind SSRF, partial-URL SSRF)
   - Auth bypass: JWT algorithm confusion, broken session fixation, password reset flaws, OAuth misconfig, insecure "remember me"
   - Authorization: IDOR, horizontal/vertical privilege escalation, mass assignment, forced browsing
   - Deserialization: Java, PHP, Python pickle, YAML, XML
   - Path traversal / LFI / RFI
   - XXE (XML External Entity)
   - Open Redirect
   - CORS misconfiguration allowing credential theft
   - Race conditions on security-sensitive operations (TOCTOU)
   - Business logic flaws with security impact
   - Cryptographic weaknesses: weak algo, hardcoded keys, predictable tokens, ECB mode
   - GraphQL: introspection abuse, batch query DoS, broken field-level auth
   - WebSocket: missing auth on upgrade, message injection
   - Prototype pollution (JavaScript)
   - ReDoS (Denial of Service via regex)
   - Cache poisoning / response splitting
   - Subdomain takeover indicators
   - Server-side request forgery via PDF/image rendering, webhooks, URL previews
   - Type confusion / unsafe type coercion
   - Insecure randomness in security contexts
   - Second-order vulnerabilities (stored payload triggered later)

For each confirmed or high-confidence finding, output a JSON object with this exact schema:

{
  "id": "VULN-{n}",
  "title": "Concise vulnerability title",
  "type": "Exact vulnerability class",
  "file": "relative/path/to/file",
  "line_start": <integer>,
  "line_end": <integer>,
  "vulnerable_code_snippet": "exact verbatim lines from source (max 20 lines)",
  "data_flow": "Describe the taint flow: where does attacker input enter, how does it travel, where does it hit the sink",
  "summary": "Plain-English explanation of the vulnerability",
  "exploitability": "Critical | High | Medium | Low",
  "exploitability_rationale": "Why is this exploitable or not? What conditions must hold?",
  "authentication_required": "None | User | Privileged User | Admin",
  "steps_to_reproduce": [
    "Step 1 ...",
    "Step 2 ...",
    "Step 3 ..."
  ],
  "proof_of_concept": "Minimal HTTP request, payload, or code snippet demonstrating the exploit (if constructable from code review alone)",
  "impact": "What can the attacker achieve if this is exploited?",
  "cvss_v3_vector": "CVSS:3.1/AV:.../AC:...",
  "cvss_v3_score": <float>,
  "mitigation": "Specific, actionable fix with example code where possible",
  "references": ["CWE-XXX", "relevant RFC or advisory if applicable"]
}

If a finding is borderline, still include it but set exploitability to "Low" and explain the uncertainty in exploitability_rationale.

Output ONLY a valid JSON array. If no exploitable vulnerability exists in this file, output: []

Source code:
\`\`\`{language}
{source_code}
\`\`\`
```

### Cross-file / multi-file reasoning

After per-file analysis, run a second pass with a cross-file context prompt for findings that may chain:

```
You are reviewing security findings across multiple files in {repo_name}. Below are individual file findings. Identify:
1. Exploit chains: where a Low/Medium finding in file A enables a High finding in file B
2. Second-order vulnerabilities: data stored insecurely in one place and consumed dangerously in another
3. Any finding that, in isolation looked limited, but combined with another becomes critical

Existing findings:
{json_findings_list}

Output any new or upgraded findings in the same JSON schema above, or output [] if no chains found.
```

---

## Step 4 — Dependency Confusion Analysis

### 4a — Extract all declared dependencies

For each package ecosystem found in the repo, parse the manifest:

| Ecosystem | Manifest Files |
|---|---|
| npm / Node.js | `package.json`, `package-lock.json`, `yarn.lock`, `.npmrc` |
| Python | `requirements.txt`, `setup.py`, `setup.cfg`, `pyproject.toml`, `Pipfile` |
| Ruby | `Gemfile`, `Gemfile.lock`, `.gemspec` |
| Go | `go.mod` |
| Java / Kotlin | `pom.xml`, `build.gradle`, `build.gradle.kts` |
| PHP | `composer.json` |
| Rust | `Cargo.toml` |
| .NET | `*.csproj`, `packages.config`, `nuget.config` |
| Docker | `Dockerfile` (`FROM` directives) |

Extract the full list of package names and versions.

### 4b — Check for internal / private package indicators

Look for signs that a package is **intended to be private / internal**:
- Package name contains the org/company name (e.g., `mycompany-utils`, `@mycompany/auth`)
- Package has a scope (`@scope/package-name`) — check if the scope is claimed on the public registry
- Package is referenced via a private registry URL in `.npmrc`, `pip.conf`, or similar config files
- Package version is `0.0.0`, `0.0.1`, or `999.999.999` — classic internal placeholder
- Package is listed in config but NOT on the public registry

### 4c — Check public registry claim status

For each suspicious package, query the public registry:

**npm:**
```
GET https://registry.npmjs.org/{package_name}
```
- If HTTP 404 → package name is **unclaimed** on public npm ← dependency confusion risk
- If HTTP 200 → check if the publisher matches the org; if not, could be squatted

**PyPI:**
```
GET https://pypi.org/pypi/{package_name}/json
```

**RubyGems:**
```
GET https://rubygems.org/api/v1/gems/{gem_name}.json
```

**For scoped npm packages (`@scope/pkg`):** also check if the scope itself is registered.

### 4d — Output per-package dependency confusion record

```json
{
  "package_name": "mycompany-internal-auth",
  "ecosystem": "npm",
  "declared_version": "1.2.0",
  "found_in_file": "package.json",
  "public_registry_status": "unclaimed | claimed-by-org | claimed-by-third-party | unknown",
  "registry_url_checked": "https://registry.npmjs.org/mycompany-internal-auth",
  "risk": "Critical | High | Medium | Low",
  "explanation": "This package name is not registered on the public npm registry. An attacker can publish a malicious package with this name at a higher version to hijack the dependency resolution.",
  "mitigation": "Register the package name on the public registry with a placeholder, pin to a specific internal registry in .npmrc with always-auth, or use a scoped private registry."
}
```

---

## Step 5 — Exploitability Analysis Pass

Before finalizing the report, run one more Claude pass over all collected findings:

```
You are performing a final exploitability triage on security findings for {repo_name}.

For each finding below, answer:
1. Is there a realistic attack path from the public internet (or as a low-privilege user)?
2. Are there compensating controls visible in the code (WAF hints, framework-level escaping, CSP, etc.) that would prevent exploitation?
3. What is the real-world impact? (data breach, account takeover, RCE, etc.)
4. Should this be CONFIRMED (definitely exploitable), LIKELY (probably exploitable, minor unknowns), UNCERTAIN (needs runtime context), or FALSE_POSITIVE (not actually exploitable)?

Update the "exploitability" and "exploitability_rationale" fields accordingly. Remove findings marked FALSE_POSITIVE from the final output.

Findings:
{all_findings_json}
```

Drop all `FALSE_POSITIVE` findings. Only confirmed, likely, and uncertain findings appear in the final report.

---

## Step 6 — Generate HTML Report

Save as `{repo_name}.html` in the current working directory.

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Report — {repo_name}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #0b0e18;
      --surface: #111827;
      --surface2: #1a2235;
      --border: #1f2d45;
      --text: #e2e8f0;
      --muted: #64748b;
      --accent: #6366f1;
      --red: #ef4444;
      --orange: #f97316;
      --yellow: #eab308;
      --green: #22c55e;
      --blue: #3b82f6;
      --purple: #a855f7;
    }
    body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.65; font-size: 15px; }
    a { color: var(--blue); text-decoration: none; }
    a:hover { text-decoration: underline; }
    code, pre { font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', monospace; }

    /* ── TOP NAV ── */
    .topbar { position: sticky; top: 0; z-index: 100; background: #080b14ee; backdrop-filter: blur(12px); border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; padding: 0 40px; height: 56px; }
    .topbar .brand { font-weight: 700; font-size: 0.95rem; color: var(--text); letter-spacing: 0.03em; }
    .topbar .repo-tag { font-size: 0.8rem; color: var(--muted); font-family: monospace; }

    /* ── HERO HEADER ── */
    .hero { background: linear-gradient(160deg, #0f172a 0%, #1a0a2e 50%, #0f1a2e 100%); padding: 60px 60px 50px; border-bottom: 1px solid var(--border); }
    .hero h1 { font-size: 2.2rem; font-weight: 800; color: #f8fafc; letter-spacing: -0.02em; }
    .hero .repo-url { color: var(--accent); font-size: 0.9rem; margin-top: 6px; font-family: monospace; }
    .hero-meta { display: flex; gap: 28px; margin-top: 22px; flex-wrap: wrap; font-size: 0.82rem; color: var(--muted); }
    .hero-meta span strong { color: #94a3b8; }

    /* ── RISK BADGES ── */
    .badge { display: inline-flex; align-items: center; padding: 2px 10px; border-radius: 999px; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; }
    .badge-critical { background: #3b0764; color: #e879f9; border: 1px solid #581c87; }
    .badge-high     { background: #450a0a; color: #f87171; border: 1px solid #7f1d1d; }
    .badge-medium   { background: #431407; color: #fb923c; border: 1px solid #7c2d12; }
    .badge-low      { background: #14532d; color: #4ade80; border: 1px solid #166534; }
    .badge-info     { background: #1e3a5f; color: #60a5fa; border: 1px solid #1d4ed8; }
    .badge-dep      { background: #312e81; color: #a5b4fc; border: 1px solid #3730a3; }

    /* ── STATS BAR ── */
    .stats { display: flex; gap: 0; border-bottom: 1px solid var(--border); overflow-x: auto; }
    .stat { flex: 1; min-width: 140px; padding: 28px 32px; border-right: 1px solid var(--border); background: var(--surface); }
    .stat:last-child { border-right: none; }
    .stat .s-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); margin-bottom: 8px; }
    .stat .s-value { font-size: 2rem; font-weight: 800; line-height: 1; }
    .stat .s-value.red    { color: var(--red); }
    .stat .s-value.orange { color: var(--orange); }
    .stat .s-value.yellow { color: var(--yellow); }
    .stat .s-value.green  { color: var(--green); }
    .stat .s-value.purple { color: var(--purple); }
    .stat .s-value.blue   { color: var(--blue); }

    /* ── LAYOUT ── */
    .layout { display: flex; min-height: calc(100vh - 56px); }
    .sidebar { width: 280px; min-width: 280px; background: var(--surface); border-right: 1px solid var(--border); padding: 24px 0; position: sticky; top: 56px; height: calc(100vh - 56px); overflow-y: auto; }
    .sidebar .s-title { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.12em; color: var(--muted); padding: 0 20px 10px; }
    .sidebar-item { display: block; padding: 8px 20px; font-size: 0.82rem; color: #94a3b8; cursor: pointer; border-left: 3px solid transparent; transition: all 0.15s; }
    .sidebar-item:hover { background: var(--surface2); color: var(--text); border-left-color: var(--accent); }
    .sidebar-item .si-id { font-family: monospace; font-size: 0.75rem; color: var(--muted); }
    .sidebar-item .si-title { display: block; font-size: 0.8rem; margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

    /* ── MAIN CONTENT ── */
    .main { flex: 1; padding: 40px 50px; min-width: 0; }
    .section-heading { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.12em; color: var(--muted); padding-bottom: 12px; border-bottom: 1px solid var(--border); margin: 48px 0 24px; }
    .section-heading:first-child { margin-top: 0; }

    /* ── FINDING CARD ── */
    .finding { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; margin-bottom: 24px; overflow: hidden; transition: border-color 0.2s; }
    .finding:hover { border-color: #334155; }
    .finding-header { display: flex; justify-content: space-between; align-items: flex-start; padding: 20px 24px; gap: 16px; }
    .finding-header-left { flex: 1; min-width: 0; }
    .finding-id { font-family: monospace; font-size: 0.72rem; color: var(--accent); font-weight: 700; margin-bottom: 4px; }
    .finding-title { font-size: 1.05rem; font-weight: 600; color: #f1f5f9; }
    .finding-type  { font-size: 0.78rem; color: var(--muted); margin-top: 4px; }
    .finding-body { padding: 0 24px 24px; border-top: 1px solid var(--border); }

    /* ── META GRID ── */
    .meta-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; padding: 18px 0; }
    .meta-item { background: var(--surface2); border-radius: 8px; padding: 10px 14px; }
    .meta-item .m-label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); margin-bottom: 4px; }
    .meta-item .m-value { font-size: 0.88rem; font-weight: 600; color: #e2e8f0; }

    /* ── DATA FLOW ── */
    .dataflow { background: #0d1117; border: 1px solid #21262d; border-left: 3px solid var(--accent); border-radius: 0 8px 8px 0; padding: 14px 18px; margin: 16px 0; font-size: 0.85rem; color: #c9d1d9; }

    /* ── CODE BLOCK ── */
    .code-wrap { margin: 16px 0; border-radius: 10px; overflow: hidden; border: 1px solid #21262d; }
    .code-header { background: #161b27; padding: 8px 16px; display: flex; justify-content: space-between; align-items: center; }
    .code-header .file-path { font-family: monospace; font-size: 0.75rem; color: #6366f1; }
    .code-header .line-ref  { font-family: monospace; font-size: 0.72rem; color: var(--muted); }
    .code-body { background: #0d1117; overflow-x: auto; }
    .code-body pre { padding: 16px; font-size: 0.8rem; color: #c9d1d9; line-height: 1.6; white-space: pre; tab-size: 2; }

    /* ── STEPS ── */
    .steps-list { list-style: none; counter-reset: steps; margin: 12px 0; }
    .steps-list li { counter-increment: steps; display: flex; gap: 14px; margin-bottom: 10px; }
    .steps-list li::before { content: counter(steps); min-width: 26px; height: 26px; background: var(--surface2); border: 1px solid var(--border); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 0.75rem; font-weight: 700; color: var(--accent); flex-shrink: 0; }
    .steps-list li span { color: #cbd5e1; font-size: 0.88rem; padding-top: 3px; }

    /* ── POC BLOCK ── */
    .poc-block { background: #070d1a; border: 1px solid #1a2540; border-radius: 8px; padding: 14px 18px; margin: 12px 0; }
    .poc-block .poc-label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.1em; color: #475569; margin-bottom: 8px; font-weight: 700; }
    .poc-block pre { font-size: 0.8rem; color: #7dd3fc; white-space: pre-wrap; word-break: break-all; }

    /* ── IMPACT / MITIGATION ── */
    .impact-block { background: #1c0a0a; border-left: 3px solid var(--red); border-radius: 0 8px 8px 0; padding: 14px 18px; margin: 14px 0; }
    .impact-block .block-label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.1em; color: #ef4444; font-weight: 700; margin-bottom: 6px; }
    .impact-block p { font-size: 0.88rem; color: #fca5a5; }
    .mitig-block { background: #052e16; border-left: 3px solid var(--green); border-radius: 0 8px 8px 0; padding: 14px 18px; margin: 14px 0; }
    .mitig-block .block-label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.1em; color: #22c55e; font-weight: 700; margin-bottom: 6px; }
    .mitig-block p { font-size: 0.88rem; color: #86efac; }
    .mitig-block pre { font-size: 0.78rem; color: #86efac; background: #031a0d; padding: 10px 14px; border-radius: 6px; margin-top: 10px; white-space: pre-wrap; }

    .field-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); font-weight: 700; margin: 18px 0 8px; }
    .field-text  { font-size: 0.88rem; color: #cbd5e1; }

    /* ── DEPENDENCY CONFUSION SECTION ── */
    .dep-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 16px; overflow: hidden; }
    .dep-card-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; background: var(--surface2); }
    .dep-card-header .pkg-name { font-family: monospace; font-size: 0.95rem; color: #e2e8f0; font-weight: 600; }
    .dep-card-body { padding: 16px 20px; }
    .dep-meta { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 12px; font-size: 0.82rem; color: var(--muted); }
    .dep-meta span strong { color: #94a3b8; }
    .dep-explanation { font-size: 0.87rem; color: #94a3b8; margin-bottom: 12px; }
    .dep-mitigation { background: #052e16; border-left: 3px solid var(--green); border-radius: 0 6px 6px 0; padding: 10px 14px; font-size: 0.84rem; color: #86efac; }

    /* ── FOOTER ── */
    .footer { background: var(--surface); border-top: 1px solid var(--border); padding: 28px 60px; display: flex; justify-content: space-between; align-items: center; font-size: 0.78rem; color: var(--muted); flex-wrap: wrap; gap: 12px; }
    .footer strong { color: #94a3b8; }

    /* ── EXPLOITABILITY STATUS BANNER ── */
    .exp-banner { display: inline-flex; align-items: center; gap: 8px; padding: 5px 12px; border-radius: 6px; font-size: 0.78rem; font-weight: 600; margin-bottom: 16px; }
    .exp-confirmed { background: #450a0a; color: #f87171; border: 1px solid #7f1d1d; }
    .exp-likely    { background: #431407; color: #fb923c; border: 1px solid #7c2d12; }
    .exp-uncertain { background: #1c1917; color: #a8a29e; border: 1px solid #44403c; }

    @media (max-width: 900px) {
      .layout { flex-direction: column; }
      .sidebar { width: 100%; position: static; height: auto; }
      .main { padding: 24px 20px; }
      .hero { padding: 32px 20px; }
      .stats { flex-wrap: wrap; }
    }
  </style>
</head>
<body>

<!-- TOP NAV -->
<nav class="topbar">
  <span class="brand">Security Audit Report</span>
  <span class="repo-tag">github.com/{owner}/{repo} @ {commit_sha_short}</span>
</nav>

<!-- HERO -->
<div class="hero">
  <h1>{repo_name}</h1>
  <div class="repo-url">https://github.com/{owner}/{repo}</div>
  <div class="hero-meta">
    <span><strong>Branch:</strong> {default_branch}</span>
    <span><strong>Commit:</strong> {commit_sha}</span>
    <span><strong>Commit Date:</strong> {commit_date}</span>
    <span><strong>Primary Language:</strong> {language}</span>
    <span><strong>Files Scanned:</strong> {files_scanned}</span>
    <span><strong>Scan Date:</strong> {scan_date}</span>
  </div>
</div>

<!-- STATS BAR -->
<div class="stats">
  <div class="stat"><div class="s-label">Total Findings</div><div class="s-value blue">{total}</div></div>
  <div class="stat"><div class="s-label">Critical</div><div class="s-value purple">{critical_count}</div></div>
  <div class="stat"><div class="s-label">High</div><div class="s-value red">{high_count}</div></div>
  <div class="stat"><div class="s-label">Medium</div><div class="s-value orange">{medium_count}</div></div>
  <div class="stat"><div class="s-label">Low</div><div class="s-value green">{low_count}</div></div>
  <div class="stat"><div class="s-label">Dep Confusion</div><div class="s-value purple">{dep_confusion_count}</div></div>
</div>

<!-- LAYOUT -->
<div class="layout">

  <!-- SIDEBAR -->
  <aside class="sidebar">
    <div class="s-title">Findings</div>
    <!-- Repeat per finding -->
    <a class="sidebar-item" href="#{finding.id}">
      <span class="si-id">{finding.id} · <span class="badge badge-{severity}">{finding.exploitability}</span></span>
      <span class="si-title">{finding.title}</span>
    </a>
    <!-- /repeat -->

    <div class="s-title" style="margin-top:24px">Dep Confusion</div>
    <a class="sidebar-item" href="#dep-confusion">
      <span class="si-title">{dep_confusion_count} packages flagged</span>
    </a>
  </aside>

  <!-- MAIN -->
  <main class="main">

    <div class="section-heading">Code Vulnerabilities</div>

    <!-- ═══ FINDING CARD (repeat per finding) ═══ -->
    <div class="finding" id="{finding.id}">
      <div class="finding-header">
        <div class="finding-header-left">
          <div class="finding-id">{finding.id}</div>
          <div class="finding-title">{finding.title}</div>
          <div class="finding-type">{finding.type}</div>
        </div>
        <span class="badge badge-{severity_class}">{finding.exploitability}</span>
      </div>
      <div class="finding-body">

        <!-- Exploitability status -->
        <div class="exp-banner exp-{exp_class}">
          {CONFIRMED | LIKELY | UNCERTAIN} — {finding.exploitability_rationale_short}
        </div>

        <!-- Meta grid -->
        <div class="meta-grid">
          <div class="meta-item"><div class="m-label">Auth Required</div><div class="m-value">{finding.authentication_required}</div></div>
          <div class="meta-item"><div class="m-label">CVSS Score</div><div class="m-value">{finding.cvss_v3_score}</div></div>
          <div class="meta-item"><div class="m-label">CVSS Vector</div><div class="m-value" style="font-size:0.7rem;font-family:monospace">{finding.cvss_v3_vector}</div></div>
          <div class="meta-item"><div class="m-label">References</div><div class="m-value">{finding.references joined by ", "}</div></div>
        </div>

        <!-- Summary -->
        <div class="field-label">Summary</div>
        <div class="field-text">{finding.summary}</div>

        <!-- Data Flow -->
        <div class="field-label">Data Flow (Source → Sink)</div>
        <div class="dataflow">{finding.data_flow}</div>

        <!-- Vulnerable code -->
        <div class="field-label">Vulnerable Code</div>
        <div class="code-wrap">
          <div class="code-header">
            <span class="file-path">{finding.file}</span>
            <span class="line-ref">Lines {finding.line_start}–{finding.line_end}</span>
          </div>
          <div class="code-body"><pre>{finding.vulnerable_code_snippet}</pre></div>
        </div>

        <!-- Steps to reproduce -->
        <div class="field-label">Steps to Reproduce</div>
        <ol class="steps-list">
          <!-- repeat per step -->
          <li><span>{step}</span></li>
        </ol>

        <!-- PoC -->
        <div class="field-label">Proof of Concept</div>
        <div class="poc-block">
          <div class="poc-label">Payload / Request</div>
          <pre>{finding.proof_of_concept}</pre>
        </div>

        <!-- Impact -->
        <div class="impact-block">
          <div class="block-label">Impact</div>
          <p>{finding.impact}</p>
        </div>

        <!-- Mitigation -->
        <div class="mitig-block">
          <div class="block-label">Mitigation</div>
          <p>{finding mitigation prose}</p>
          <pre>{finding mitigation code example if applicable}</pre>
        </div>

      </div>
    </div>
    <!-- ═══ /FINDING CARD ═══ -->


    <!-- ═══ DEPENDENCY CONFUSION SECTION ═══ -->
    <div class="section-heading" id="dep-confusion">Dependency Confusion Analysis</div>

    <!-- repeat per flagged package -->
    <div class="dep-card">
      <div class="dep-card-header">
        <span class="pkg-name">{package_name}</span>
        <span class="badge badge-dep">{dep.risk} · {dep.ecosystem}</span>
      </div>
      <div class="dep-card-body">
        <div class="dep-meta">
          <span><strong>Declared Version:</strong> {dep.declared_version}</span>
          <span><strong>Found In:</strong> {dep.found_in_file}</span>
          <span><strong>Registry Status:</strong> {dep.public_registry_status}</span>
          <span><strong>Registry Checked:</strong> <a href="{dep.registry_url_checked}" target="_blank">{dep.registry_url_checked}</a></span>
        </div>
        <div class="dep-explanation">{dep.explanation}</div>
        <div class="dep-mitigation">{dep.mitigation}</div>
      </div>
    </div>
    <!-- /repeat -->

  </main>
</div>

<!-- FOOTER -->
<div class="footer">
  <span>Generated by <strong>Claude Security Scanner</strong></span>
  <span>Repository: <strong>github.com/{owner}/{repo}</strong> · Commit: <strong>{commit_sha_short}</strong></span>
  <span>Scan Date: <strong>{scan_date}</strong></span>
  <span style="color:#374151">For authorized security research and responsible disclosure only.</span>
</div>

</body>
</html>
```

---

## Step 7 — Console Summary

After the scan completes, print:

```
╔══════════════════════════════════════════════════════════╗
║  SCAN COMPLETE — {repo_name}
╠══════════════════════════════════════════════════════════╣
║  Repo       : https://github.com/{owner}/{repo}
║  Commit     : {commit_sha}
║  Files      : {files_scanned} scanned
║  Findings   : {total}  (Critical: {c}  High: {h}  Medium: {m}  Low: {l})
║  Dep Conf.  : {dep_confusion_count} packages flagged
║  Report     : {repo_name}.html
╚══════════════════════════════════════════════════════════╝
```

---

## Implementation Notes

### Tools to Use
| Task | Tool |
|---|---|
| Clone repo | `Bash` — `git clone` |
| Walk file tree | `Bash` — `find` or `Glob` |
| Read source files | `Read` |
| Query npm/PyPI/RubyGems APIs | `WebFetch` |
| LLM code analysis | Claude (self) via prompt above |
| Write HTML report | `Write` |

### Chunking Strategy
- Files ≤ 300 lines → analyze in one prompt
- Files 301–800 lines → split into 350-line chunks with 50-line overlap
- Files > 800 lines → split into 400-line chunks with 80-line overlap
- Deduplicate findings across chunks by `(file, line_start)` before final output

### Language Awareness
Adjust taint-flow reasoning per language:
- **PHP**: `$_GET`, `$_POST`, `$_REQUEST`, `$_FILES`, `$_COOKIE` are sources; `echo`, `print`, SQL query strings, `system()`, `eval()` are sinks
- **Node.js / TypeScript**: `req.query`, `req.body`, `req.params`, `req.headers` are sources; `res.send` with unescaped content, `child_process.exec`, template literals in SQL are sinks
- **Python**: `request.args`, `request.form`, `request.json` are sources; `render_template_string`, `subprocess.call`, `eval`, ORM `.raw()` are sinks
- **Go**: `r.URL.Query()`, `r.FormValue`, `r.Body` are sources; `template.HTML()` casts, `os/exec`, format strings with user input are sinks
- **Java**: `HttpServletRequest.getParameter()` is source; `Runtime.exec()`, JDBC `Statement.execute()`, `PrintWriter.print()` without encoding are sinks
- **Ruby on Rails**: `params[]` is source; `raw`, `html_safe`, `exec`, `.where("... #{}")` are sinks

### What NOT to Report
- Missing security headers (CSP, HSTS) — not code vulnerabilities
- Use of deprecated functions with no exploitable path
- Verbose error messages unless they leak secrets or enable enumeration attacks
- Self-XSS (requires the victim to run their own payload)
- Clickjacking without demonstrated impact
- Rate limiting absence unless it enables credential stuffing with a clear endpoint

### Dependency Confusion — False Positive Avoidance
- Only flag packages that are referenced as a **dependency to be installed** (not just mentioned in docs)
- If a package is scoped AND the scope is registered by the correct org → low risk, note it but don't flag as critical
- If `.npmrc` / `pip.conf` explicitly pins to an internal registry URL → medium risk (misconfigured resolver could still pull public)
- If no private registry is configured AND the package is not on the public registry → Critical

---

## Security & Ethics

- This skill performs **static source code analysis only** — no active exploitation, no live HTTP requests to the target application
- All findings are for **responsible disclosure** purposes
- Do not scan repositories you do not have authorization to audit
- Follow responsible disclosure: notify maintainers privately before publishing findings
