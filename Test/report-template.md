# Model File Vulnerability Report — HTML Template

Save the completed report as `report.html` (or user-specified name) in the current
working directory. Replace all `{placeholder}` values with actual content.

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Model File Vulnerability Report — {repo_name}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #09090f;
      --surface: #0f1117;
      --surface2: #161b27;
      --surface3: #1a2235;
      --border: #1e2d42;
      --text: #e2e8f0;
      --muted: #566a82;
      --accent: #818cf8;
      --red: #f87171;
      --orange: #fb923c;
      --yellow: #facc15;
      --green: #4ade80;
      --blue: #60a5fa;
      --purple: #c084fc;
      --teal: #2dd4bf;
    }
    body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.65; font-size: 15px; }
    a { color: var(--blue); text-decoration: none; }
    a:hover { text-decoration: underline; }
    code, pre { font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace; }

    /* TOP NAV */
    .topbar { position: sticky; top: 0; z-index: 100; background: #06080fee; backdrop-filter: blur(14px); border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; padding: 0 40px; height: 56px; }
    .topbar .brand { font-weight: 700; font-size: 0.9rem; color: var(--text); display: flex; align-items: center; gap: 10px; }
    .topbar .brand .icon { font-size: 1.1rem; }
    .topbar .repo-tag { font-size: 0.78rem; color: var(--muted); font-family: monospace; }

    /* HERO */
    .hero { background: linear-gradient(140deg, #0a0d1a 0%, #150820 45%, #0a1220 100%); padding: 56px 60px 44px; border-bottom: 1px solid var(--border); }
    .hero h1 { font-size: 2rem; font-weight: 800; color: #f1f5f9; letter-spacing: -0.02em; }
    .hero .sub { color: var(--muted); font-size: 0.88rem; margin-top: 6px; font-family: monospace; }
    .hero-meta { display: flex; gap: 24px; margin-top: 20px; flex-wrap: wrap; font-size: 0.8rem; color: var(--muted); }
    .hero-meta span strong { color: #94a3b8; }

    /* BADGES */
    .badge { display: inline-flex; align-items: center; padding: 2px 9px; border-radius: 999px; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; }
    .badge-critical { background: #3b0764; color: #e879f9; border: 1px solid #6b21a8; }
    .badge-high     { background: #450a0a; color: #f87171; border: 1px solid #991b1b; }
    .badge-medium   { background: #431407; color: #fb923c; border: 1px solid #9a3412; }
    .badge-low      { background: #052e16; color: #4ade80; border: 1px solid #166534; }
    .badge-info     { background: #1e3a5f; color: #60a5fa; border: 1px solid #1d4ed8; }

    /* STATS BAR */
    .stats { display: flex; border-bottom: 1px solid var(--border); overflow-x: auto; }
    .stat { flex: 1; min-width: 120px; padding: 22px 28px; border-right: 1px solid var(--border); background: var(--surface); }
    .stat:last-child { border-right: none; }
    .stat .s-label { font-size: 0.67rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); margin-bottom: 8px; }
    .stat .s-value { font-size: 1.8rem; font-weight: 800; line-height: 1; }
    .stat .s-value.purple { color: var(--purple); }
    .stat .s-value.red    { color: var(--red); }
    .stat .s-value.orange { color: var(--orange); }
    .stat .s-value.green  { color: var(--green); }
    .stat .s-value.blue   { color: var(--blue); }
    .stat .s-value.teal   { color: var(--teal); }

    /* LAYOUT */
    .layout { display: flex; min-height: calc(100vh - 56px); }
    .sidebar { width: 270px; min-width: 270px; background: var(--surface); border-right: 1px solid var(--border); padding: 20px 0; position: sticky; top: 56px; height: calc(100vh - 56px); overflow-y: auto; }
    .sidebar-section { font-size: 0.62rem; text-transform: uppercase; letter-spacing: 0.12em; color: var(--muted); padding: 16px 18px 8px; }
    .sidebar-item { display: flex; flex-direction: column; padding: 8px 18px; cursor: pointer; border-left: 3px solid transparent; transition: all 0.15s; text-decoration: none; }
    .sidebar-item:hover { background: var(--surface2); border-left-color: var(--accent); }
    .sidebar-item .si-id { font-family: monospace; font-size: 0.7rem; color: var(--muted); display: flex; align-items: center; gap: 6px; }
    .sidebar-item .si-title { font-size: 0.78rem; color: #94a3b8; margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .sidebar-divider { height: 1px; background: var(--border); margin: 8px 0; }

    /* MAIN */
    .main { flex: 1; padding: 36px 48px; min-width: 0; }
    .section-title { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.12em; color: var(--muted); padding-bottom: 10px; border-bottom: 1px solid var(--border); margin: 44px 0 20px; }
    .section-title:first-child { margin-top: 0; }

    /* SUMMARY TABLE */
    .summary-table { width: 100%; border-collapse: collapse; margin: 0 0 32px; font-size: 0.83rem; }
    .summary-table th { background: var(--surface2); color: var(--muted); font-size: 0.67rem; text-transform: uppercase; letter-spacing: 0.1em; padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }
    .summary-table td { padding: 10px 14px; border-bottom: 1px solid var(--border); color: #cbd5e1; vertical-align: middle; }
    .summary-table tr:hover td { background: var(--surface2); }
    .summary-table .sev-col { width: 90px; }
    .summary-table .id-col { font-family: monospace; font-size: 0.75rem; color: var(--accent); }
    .summary-table .file-col { font-family: monospace; font-size: 0.75rem; color: #64748b; }

    /* FINDING CARD */
    .finding { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; margin-bottom: 20px; overflow: hidden; scroll-margin-top: 70px; }
    .finding:hover { border-color: #2a3a52; }
    .finding-header { display: flex; justify-content: space-between; align-items: flex-start; padding: 18px 22px; gap: 14px; }
    .finding-header-left { flex: 1; min-width: 0; }
    .finding-id   { font-family: monospace; font-size: 0.7rem; color: var(--accent); font-weight: 700; margin-bottom: 3px; }
    .finding-title { font-size: 1.02rem; font-weight: 600; color: #f1f5f9; }
    .finding-class { font-size: 0.77rem; color: var(--muted); margin-top: 3px; }
    .finding-body { padding: 0 22px 22px; border-top: 1px solid var(--border); }

    /* META GRID */
    .meta-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 10px; padding: 16px 0 6px; }
    .meta-item { background: var(--surface2); border-radius: 8px; padding: 9px 13px; }
    .meta-item .m-label { font-size: 0.62rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); margin-bottom: 3px; }
    .meta-item .m-value { font-size: 0.85rem; font-weight: 600; color: #e2e8f0; }
    .meta-item .m-value.mono { font-family: monospace; font-size: 0.72rem; }

    /* ATTACK SCENARIO */
    .scenario-block { background: var(--surface2); border-left: 3px solid var(--accent); border-radius: 0 8px 8px 0; padding: 12px 16px; margin: 14px 0; font-size: 0.84rem; color: #cbd5e1; }
    .scenario-block .scenario-label { font-size: 0.62rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--accent); font-weight: 700; margin-bottom: 6px; }

    /* CODE BLOCK */
    .code-wrap { margin: 14px 0; border-radius: 10px; overflow: hidden; border: 1px solid #1a2640; }
    .code-header { background: #0f1623; padding: 7px 14px; display: flex; justify-content: space-between; align-items: center; }
    .code-header .file-path { font-family: monospace; font-size: 0.72rem; color: var(--accent); }
    .code-header .line-ref  { font-family: monospace; font-size: 0.68rem; color: var(--muted); }
    .code-header .gh-link   { font-size: 0.68rem; color: var(--blue); }
    .code-body { background: #090e1a; overflow-x: auto; }
    .code-body pre { padding: 14px 16px; font-size: 0.78rem; color: #c9d1d9; line-height: 1.65; white-space: pre; tab-size: 2; }

    /* STEPS */
    .steps-list { list-style: none; counter-reset: steps; margin: 10px 0; }
    .steps-list li { counter-increment: steps; display: flex; gap: 12px; margin-bottom: 9px; }
    .steps-list li::before { content: counter(steps); min-width: 24px; height: 24px; background: var(--surface2); border: 1px solid var(--border); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 0.72rem; font-weight: 700; color: var(--accent); flex-shrink: 0; }
    .steps-list li span { color: #cbd5e1; font-size: 0.85rem; padding-top: 2px; }

    /* POC BLOCK */
    .poc-block { background: #050c1a; border: 1px solid #12244a; border-radius: 8px; margin: 12px 0; overflow: hidden; }
    .poc-block-header { background: #091226; padding: 7px 14px; display: flex; justify-content: space-between; align-items: center; }
    .poc-block-header .poc-label { font-size: 0.62rem; text-transform: uppercase; letter-spacing: 0.1em; color: #4a6fa5; font-weight: 700; }
    .poc-block-header .poc-sublabel { font-size: 0.68rem; color: var(--muted); }
    .poc-block pre { padding: 14px 16px; font-size: 0.78rem; color: #7dd3fc; white-space: pre-wrap; word-break: break-all; line-height: 1.6; }

    /* HUGGINGFACE POC */
    .hf-block { background: #0a1020; border: 1px solid #1a3050; border-radius: 8px; margin: 12px 0; overflow: hidden; }
    .hf-block-header { background: #0d1830; padding: 7px 14px; display: flex; align-items: center; gap: 8px; }
    .hf-block-header .hf-label { font-size: 0.62rem; text-transform: uppercase; letter-spacing: 0.1em; color: #fbbf24; font-weight: 700; }
    .hf-block pre { padding: 14px 16px; font-size: 0.78rem; color: #fde68a; white-space: pre-wrap; line-height: 1.6; }

    /* IMPACT / MITIGATION */
    .impact-block { background: #1c0a0a; border-left: 3px solid var(--red); border-radius: 0 8px 8px 0; padding: 12px 16px; margin: 12px 0; }
    .impact-block .block-label { font-size: 0.62rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--red); font-weight: 700; margin-bottom: 5px; }
    .impact-block p { font-size: 0.85rem; color: #fca5a5; }
    .mitig-block { background: #031a0d; border-left: 3px solid var(--green); border-radius: 0 8px 8px 0; padding: 12px 16px; margin: 12px 0; }
    .mitig-block .block-label { font-size: 0.62rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--green); font-weight: 700; margin-bottom: 5px; }
    .mitig-block p { font-size: 0.85rem; color: #86efac; margin-bottom: 8px; }
    .mitig-block pre { font-size: 0.76rem; color: #86efac; background: #021008; padding: 10px 12px; border-radius: 6px; white-space: pre-wrap; }

    .field-label { font-size: 0.67rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); font-weight: 700; margin: 16px 0 7px; }
    .field-text  { font-size: 0.85rem; color: #cbd5e1; }

    /* FORMATS TABLE */
    .formats-section { margin: 0 0 32px; }
    .formats-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; }
    .format-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }
    .format-card .fc-ext { font-family: monospace; font-size: 0.88rem; color: var(--accent); font-weight: 600; }
    .format-card .fc-count { font-size: 0.78rem; color: var(--muted); margin-top: 4px; }
    .format-card .fc-risk { font-size: 0.7rem; margin-top: 6px; }

    /* REMEDIATION ROADMAP */
    .roadmap { margin: 0 0 32px; }
    .roadmap-item { display: flex; gap: 16px; margin-bottom: 14px; padding: 14px 16px; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; }
    .roadmap-priority { font-family: monospace; font-size: 0.72rem; font-weight: 700; padding: 3px 8px; border-radius: 4px; height: fit-content; flex-shrink: 0; }
    .p0 { background: #3b0764; color: #e879f9; }
    .p1 { background: #450a0a; color: #f87171; }
    .p2 { background: #431407; color: #fb923c; }
    .p3 { background: #052e16; color: #4ade80; }
    .roadmap-content .rc-title { font-size: 0.9rem; font-weight: 600; color: #f1f5f9; margin-bottom: 4px; }
    .roadmap-content .rc-desc { font-size: 0.82rem; color: #94a3b8; }
    .roadmap-content .rc-ids { font-size: 0.75rem; color: var(--muted); margin-top: 4px; font-family: monospace; }

    /* FOOTER */
    .footer { background: var(--surface); border-top: 1px solid var(--border); padding: 24px 60px; display: flex; justify-content: space-between; align-items: center; font-size: 0.76rem; color: var(--muted); flex-wrap: wrap; gap: 10px; }
    .footer strong { color: #94a3b8; }

    @media (max-width: 900px) {
      .layout { flex-direction: column; }
      .sidebar { width: 100%; position: static; height: auto; }
      .main { padding: 20px 16px; }
      .hero { padding: 28px 20px; }
    }
  </style>
</head>
<body>

<!-- TOP NAV -->
<nav class="topbar">
  <span class="brand"><span class="icon">&#x26A0;</span> Model File Vulnerability Report</span>
  <span class="repo-tag">{repo_url} &mdash; scanned {scan_date}</span>
</nav>

<!-- HERO -->
<div class="hero">
  <h1>{repo_name}</h1>
  <div class="sub">{repo_url}</div>
  <div class="hero-meta">
    <span><strong>Branch:</strong> {branch}</span>
    <span><strong>Commit:</strong> {commit_sha}</span>
    <span><strong>Scan Date:</strong> {scan_date}</span>
    <span><strong>Files Scanned:</strong> {files_scanned}</span>
    <span><strong>Model Files Found:</strong> {model_files_count}</span>
    <span><strong>Formats:</strong> {formats_found}</span>
  </div>
</div>

<!-- STATS BAR -->
<div class="stats">
  <div class="stat"><div class="s-label">Total Findings</div><div class="s-value blue">{total}</div></div>
  <div class="stat"><div class="s-label">Critical</div><div class="s-value purple">{critical_count}</div></div>
  <div class="stat"><div class="s-label">High</div><div class="s-value red">{high_count}</div></div>
  <div class="stat"><div class="s-label">Medium</div><div class="s-value orange">{medium_count}</div></div>
  <div class="stat"><div class="s-label">Low</div><div class="s-value green">{low_count}</div></div>
  <div class="stat"><div class="s-label">Formats at Risk</div><div class="s-value teal">{risky_formats_count}</div></div>
</div>

<!-- LAYOUT -->
<div class="layout">

  <!-- SIDEBAR -->
  <aside class="sidebar">
    <div class="sidebar-section">Findings</div>
    <!--
      Repeat per finding:
      <a class="sidebar-item" href="#{finding.id}">
        <span class="si-id">
          {finding.id}
          <span class="badge badge-{severity_class}">{severity}</span>
        </span>
        <span class="si-title">{finding.title}</span>
      </a>
    -->

    <div class="sidebar-divider"></div>
    <div class="sidebar-section">Navigation</div>
    <a class="sidebar-item" href="#summary-table"><span class="si-title">Summary Table</span></a>
    <a class="sidebar-item" href="#formats-section"><span class="si-title">Formats Analyzed</span></a>
    <a class="sidebar-item" href="#remediation-roadmap"><span class="si-title">Remediation Roadmap</span></a>
  </aside>

  <!-- MAIN -->
  <main class="main">

    <!-- ====== SUMMARY TABLE ====== -->
    <div class="section-title" id="summary-table">Findings Summary</div>
    <table class="summary-table">
      <thead>
        <tr>
          <th class="sev-col">Severity</th>
          <th>ID</th>
          <th>Vulnerability</th>
          <th>Format</th>
          <th>File</th>
          <th>CWE</th>
          <th>CVSS</th>
        </tr>
      </thead>
      <tbody>
        <!--
          Repeat per finding:
          <tr>
            <td><span class="badge badge-{severity_class}">{severity}</span></td>
            <td class="id-col">{finding.id}</td>
            <td><a href="#{finding.id}">{finding.title}</a></td>
            <td><code>{finding.format}</code></td>
            <td class="file-col">{finding.file}:{finding.line}</td>
            <td><a href="https://cwe.mitre.org/data/definitions/{cwe_num}.html" target="_blank">{finding.cwe}</a></td>
            <td>{finding.cvss_score}</td>
          </tr>
        -->
      </tbody>
    </table>

    <!-- ====== FORMATS SECTION ====== -->
    <div class="section-title" id="formats-section">Model Formats Analyzed</div>
    <div class="formats-section">
      <div class="formats-grid">
        <!--
          Repeat per format found:
          <div class="format-card">
            <div class="fc-ext">{extension}</div>
            <div class="fc-count">{count} file(s) found</div>
            <div class="fc-risk"><span class="badge badge-{risk_class}">{risk_level}</span></div>
          </div>
        -->
      </div>
    </div>

    <!-- ====== FINDINGS ====== -->
    <div class="section-title">Confirmed Vulnerabilities</div>

    <!--
    ============================================================
    FINDING CARD — repeat this block for each confirmed finding
    ============================================================
    -->
    <div class="finding" id="{finding.id}">
      <div class="finding-header">
        <div class="finding-header-left">
          <div class="finding-id">{finding.id} &bull; {finding.format} &bull; {finding.cwe}</div>
          <div class="finding-title">{finding.title}</div>
          <div class="finding-class">{finding.vulnerability_class}</div>
        </div>
        <span class="badge badge-{severity_class}">{severity}</span>
      </div>
      <div class="finding-body">

        <!-- Meta grid -->
        <div class="meta-grid">
          <div class="meta-item">
            <div class="m-label">Format</div>
            <div class="m-value mono">{finding.format}</div>
          </div>
          <div class="meta-item">
            <div class="m-label">CVSS Score</div>
            <div class="m-value">{finding.cvss_score}</div>
          </div>
          <div class="meta-item">
            <div class="m-label">CVSS Vector</div>
            <div class="m-value mono" style="font-size:0.65rem">{finding.cvss_vector}</div>
          </div>
          <div class="meta-item">
            <div class="m-label">CWE</div>
            <div class="m-value"><a href="https://cwe.mitre.org/data/definitions/{cwe_num}.html" target="_blank">{finding.cwe}</a></div>
          </div>
          <div class="meta-item">
            <div class="m-label">Auth Required</div>
            <div class="m-value">{finding.auth_required}</div>
          </div>
          <div class="meta-item">
            <div class="m-label">User Interaction</div>
            <div class="m-value">{finding.user_interaction}</div>
          </div>
        </div>

        <!-- Attack Scenario -->
        <div class="field-label">Attack Scenario</div>
        <div class="scenario-block">
          <div class="scenario-label">Who / What / How</div>
          {finding.attack_scenario}
        </div>

        <!-- Vulnerable Code -->
        <div class="field-label">Vulnerable Code</div>
        <div class="code-wrap">
          <div class="code-header">
            <span class="file-path">{finding.file}</span>
            <span class="line-ref">Lines {finding.line_start}&ndash;{finding.line_end}</span>
            <!--
              If GitHub repo, add:
              <a class="gh-link" href="{github_blob_url}#L{finding.line_start}-L{finding.line_end}" target="_blank">View on GitHub &#8599;</a>
            -->
          </div>
          <div class="code-body"><pre>{finding.vulnerable_code_snippet}</pre></div>
        </div>

        <!-- Description -->
        <div class="field-label">Description</div>
        <div class="field-text">{finding.description}</div>

        <!-- Steps to Reproduce -->
        <div class="field-label">Steps to Reproduce</div>
        <ol class="steps-list">
          <!--
            Repeat per step:
            <li><span>{step text}</span></li>
          -->
        </ol>

        <!-- PoC: Malicious Model Creation -->
        <div class="field-label">Proof of Concept &mdash; Create Malicious Model</div>
        <div class="poc-block">
          <div class="poc-block-header">
            <span class="poc-label">Model Creation Code</span>
            <span class="poc-sublabel">Run this to generate the malicious model file</span>
          </div>
          <pre>{finding.poc_create_code}</pre>
        </div>

        <!-- PoC: Trigger / Load -->
        <div class="field-label">Proof of Concept &mdash; Trigger Execution</div>
        <div class="poc-block">
          <div class="poc-block-header">
            <span class="poc-label">Victim Load Code</span>
            <span class="poc-sublabel">Loading this model triggers the payload</span>
          </div>
          <pre>{finding.poc_trigger_code}</pre>
        </div>

        <!-- HuggingFace PoC -->
        <!--
          Include only if applicable (model file can be hosted on HuggingFace)
        -->
        <div class="field-label">HuggingFace PoC Setup</div>
        <div class="hf-block">
          <div class="hf-block-header">
            <span class="hf-label">HuggingFace PoC</span>
          </div>
          <pre>
# Step 1: Create a HuggingFace repository
#   Go to: https://huggingface.co/new
#   Repository name: model-file-poc-{finding.id.lower()}
#   Set visibility: Private (for responsible disclosure) or Public (for demo)

# Step 2: Generate the malicious model file (see PoC above)
python3 create_malicious_model.py
# Output: {finding.poc_filename}

# Step 3: Upload to HuggingFace
pip install huggingface_hub
huggingface-cli login
huggingface-cli upload {hf_username}/model-file-poc-{finding.id.lower()} \
    {finding.poc_filename} {finding.poc_filename}

# Step 4: Victim loads the model (demonstrates full attack chain)
{finding.poc_hf_victim_code}

# Expected result: {finding.poc_expected_result}
# Verify: ls /tmp/poc_{finding.id.lower()}
          </pre>
        </div>

        <!-- Impact -->
        <div class="impact-block">
          <div class="block-label">Impact</div>
          <p>{finding.impact}</p>
        </div>

        <!-- Mitigation -->
        <div class="mitig-block">
          <div class="block-label">Mitigation</div>
          <p>{finding.mitigation_description}</p>
          <pre>{finding.mitigation_code}</pre>
        </div>

        <!-- References -->
        <div class="field-label">References</div>
        <div class="field-text">
          <!--
            <a href="{ref_url}" target="_blank">{ref_label}</a> &bull;
          -->
        </div>

      </div>
    </div>
    <!-- ============================================================ END FINDING CARD -->


    <!-- ====== REMEDIATION ROADMAP ====== -->
    <div class="section-title" id="remediation-roadmap">Remediation Roadmap</div>
    <div class="roadmap">

      <div class="roadmap-item">
        <span class="roadmap-priority p0">P0</span>
        <div class="roadmap-content">
          <div class="rc-title">Immediate: Disable Unsafe Model Loading (Critical findings)</div>
          <div class="rc-desc">
            Immediately add <code>weights_only=True</code> to all <code>torch.load()</code> calls.
            Block model uploads until format validation is enforced. Add scanner for pickle magic
            bytes in all accepted model formats.
          </div>
          <div class="rc-ids">Addresses: {critical_finding_ids}</div>
        </div>
      </div>

      <div class="roadmap-item">
        <span class="roadmap-priority p1">P1</span>
        <div class="roadmap-content">
          <div class="rc-title">Short-term: Enforce Safe Formats &amp; Validate Sources</div>
          <div class="rc-desc">
            Migrate model storage to safetensors or ONNX (without custom ops). Add source
            allowlisting for model downloads (only verified HuggingFace repos, internal artifact
            store). Scan Keras .h5 files for Lambda layer presence before serving.
          </div>
          <div class="rc-ids">Addresses: {high_finding_ids}</div>
        </div>
      </div>

      <div class="roadmap-item">
        <span class="roadmap-priority p2">P2</span>
        <div class="roadmap-content">
          <div class="rc-title">Medium-term: Harden Parser Implementations</div>
          <div class="rc-desc">
            Add bounds checking on GGUF header fields (n_kv, n_tensors). Add integer overflow
            checks on all allocation size computations in model parsers. Validate SafeTensors
            header size and tensor offsets before reading.
          </div>
          <div class="rc-ids">Addresses: {medium_finding_ids}</div>
        </div>
      </div>

      <div class="roadmap-item">
        <span class="roadmap-priority p3">P3</span>
        <div class="roadmap-content">
          <div class="rc-title">Long-term: Model Supply Chain Integrity</div>
          <div class="rc-desc">
            Implement cryptographic signing for all model files. Verify signatures before loading.
            Add runtime behavioral monitoring to detect inference-time backdoors. Maintain an
            approved list of model sources and formats.
          </div>
          <div class="rc-ids">Addresses: scanner bypass, backdoor, supply chain findings</div>
        </div>
      </div>

    </div>

  </main>
</div>

<!-- FOOTER -->
<div class="footer">
  <span>Generated by <strong>Model File Vulnerability Scanner</strong></span>
  <span>Repository: <strong>{repo_url}</strong></span>
  <span>Scan Date: <strong>{scan_date}</strong></span>
  <span style="color:#374151">For authorized security research and responsible disclosure only. PoC models use non-destructive payloads.</span>
</div>

</body>
</html>
```

---

## Report Generation Instructions

### Variable Substitution Reference

| Placeholder | Value |
|---|---|
| `{repo_name}` | Repository name (e.g., `my-ml-service`) |
| `{repo_url}` | Full repository URL |
| `{branch}` | Default branch name |
| `{commit_sha}` | Full commit SHA |
| `{scan_date}` | ISO 8601 date of scan (e.g., `2026-03-12`) |
| `{files_scanned}` | Total number of source files analyzed |
| `{model_files_count}` | Number of model files found |
| `{formats_found}` | Comma-separated list of extensions found |
| `{total}` | Total confirmed finding count |
| `{critical_count}` | Count of CRITICAL findings |
| `{high_count}` | Count of HIGH findings |
| `{medium_count}` | Count of MEDIUM findings |
| `{low_count}` | Count of LOW findings |
| `{risky_formats_count}` | Number of formats with at least one finding |
| `{finding.id}` | Finding ID (e.g., `MVS-001`) |
| `{severity_class}` | CSS class: `critical`, `high`, `medium`, `low` |
| `{finding.format}` | Model format (e.g., `.pt`, `.h5`, `.gguf`) |
| `{finding.cwe}` | CWE identifier (e.g., `CWE-502`) |
| `{cwe_num}` | CWE number only (e.g., `502`) |
| `{finding.cvss_score}` | CVSS 3.1 score (e.g., `9.8`) |
| `{finding.cvss_vector}` | Full CVSS vector string |
| `{finding.file}` | Relative file path |
| `{finding.line_start}` | Start line number |
| `{finding.line_end}` | End line number |
| `{github_blob_url}` | `{repo_url}/blob/{commit_sha}/{file_path}` |
| `{finding.poc_filename}` | Name of the generated malicious model file |
| `{hf_username}` | Placeholder for researcher's HF username |
| `{finding.poc_hf_victim_code}` | Code showing victim loading model from HF |
| `{finding.poc_expected_result}` | What should happen (e.g., `/tmp/poc_mvs001 created`) |

### Finding ID Format
Use `MVS-{NNN}` format, ordered by severity (Critical first, then High, Medium, Low).
Example: `MVS-001`, `MVS-002`, ..., `MVS-015`

### GitHub Permalink Construction
For GitHub repos, construct vulnerability line links as:
```
https://github.com/{owner}/{repo}/blob/{commit_sha}/{relative_file_path}#L{line_start}-L{line_end}
```

### PoC Safety Rules
- Always use `touch /tmp/poc_{finding_id}` as the PoC command — never destructive commands
- For HuggingFace PoCs, note: "Use a private repository during responsible disclosure"
- Label all PoC model files clearly in their filename: `malicious_`, `poc_`, or `vuln_`
