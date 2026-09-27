import os
import re
import time
from collections import deque
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
import streamlit as st

# ----------------- CONFIGURATION & CRT THEME -----------------
st.set_page_config(
    page_title="CRT Cyber Squad | Enterprise Vulnerability Auditor",
    page_icon="🤖",
    layout="wide"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Bungee&display=swap');

    .stApp {
        background-color: #f4f1ea;
        color: #1a1a1a;
        font-family: 'Share Tech Mono', monospace;
    }

    /* 2x2 Agent Grid */
    .agent-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 16px;
        margin-bottom: 24px;
    }
    .agent-card {
        background-color: #ffffff;
        border: 3px solid #222;
        border-radius: 8px;
        padding: 14px;
        box-shadow: 4px 4px 0px #000;
    }
    .agent-title {
        font-family: 'Bungee', monospace;
        font-size: 13px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 8px;
    }
    .agent-screen {
        background-color: #1a2419;
        color: #4af626;
        border: 2px solid #333;
        border-radius: 4px;
        padding: 8px 12px;
        font-size: 12px;
        min-height: 50px;
        box-shadow: inset 0 0 6px rgba(0,0,0,0.8);
    }

    .badge-idle { background-color: #616161; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; }
    .badge-active { background-color: #2e7d32; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; }

    /* Audit Finding Cards */
    .vuln-card {
        background: #ffffff;
        border: 2px solid #222;
        border-radius: 6px;
        padding: 16px;
        margin-bottom: 16px;
        box-shadow: 3px 3px 0px #333;
    }
    .vuln-card.high { border-left: 8px solid #c62828; }
    .vuln-card.medium { border-left: 8px solid #ef6c00; }
    .vuln-card.low { border-left: 8px solid #1565c0; }

    .evidence-block {
        background-color: #fffde7;
        border: 1px dashed #fbc02d;
        padding: 8px 12px;
        border-radius: 4px;
        margin: 8px 0;
        font-size: 13px;
    }
    .remediation-block {
        background-color: #e8f5e9;
        border: 1px solid #81c784;
        padding: 10px 14px;
        border-radius: 4px;
        margin-top: 8px;
    }
    .code-snippet {
        background: #21252b;
        color: #98c379;
        padding: 8px 12px;
        border-radius: 4px;
        font-size: 12px;
        overflow-x: auto;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- RECON & DETERMINISTIC AUDIT ENGINE -----------------

def get_base_domain(host: str) -> str:
    """Extracts base registered domain to manage subdomain inclusion bounds."""
    parts = host.split('.')
    return ".".join(parts[-2:]) if len(parts) > 2 else host

def execute_deterministic_crawl(start_url: str, max_pages: int = 10, scan_subdomains: bool = True):
    """
    Traverses routes within authorized domain scope and captures response telemetry.
    """
    root_parsed = urlparse(start_url)
    root_domain = get_base_domain(root_parsed.netloc)
    visited = set()
    queue = deque([start_url])
    records = []

    headers = {"User-Agent": "CRTSquad-DefensiveAuditor/4.0 (Non-Offensive Security Scanner)"}

    while queue and len(visited) < max_pages:
        target = queue.popleft()
        if target in visited:
            continue
        visited.add(target)

        try:
            start_time = time.time()
            resp = requests.get(target, headers=headers, timeout=6, allow_redirects=True)
            latency_ms = round((time.time() - start_time) * 1000, 2)

            resp_headers = dict(resp.headers)
            content_type = resp_headers.get("Content-Type", "")
            forms = []
            discovered_links = []

            if "text/html" in content_type:
                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract forms and field attributes
                for idx, form_tag in enumerate(soup.find_all("form")):
                    action = urljoin(target, form_tag.get("action", ""))
                    method = form_tag.get("method", "GET").upper()
                    inputs = []
                    for input_tag in form_tag.find_all(["input", "textarea", "select"]):
                        inputs.append({
                            "name": input_tag.get("name", "unnamed"),
                            "type": input_tag.get("type", "text"),
                            "id": input_tag.get("id", "")
                        })
                    forms.append({
                        "id": idx + 1,
                        "action": action,
                        "method": method,
                        "inputs": inputs
                    })

                # Link extraction with scope validation
                for anchor in soup.find_all("a", href=True):
                    resolved = urljoin(target, anchor['href'].strip())
                    link_parsed = urlparse(resolved)

                    # Normalize out anchors and query parameters for crawling queue
                    clean_url = f"{link_parsed.scheme}://{link_parsed.netloc}{link_parsed.path}"
                    link_domain = link_parsed.netloc

                    is_scoped = False
                    if scan_subdomains:
                        is_scoped = link_domain == root_domain or link_domain.endswith(f".{root_domain}")
                    else:
                        is_scoped = link_domain == root_parsed.netloc

                    if is_scoped and clean_url not in visited and clean_url not in queue:
                        if resolved.startswith(("http://", "https://")):
                            discovered_links.append(resolved)
                            queue.append(clean_url)

            records.append({
                "url": target,
                "status": resp.status_code,
                "latency_ms": latency_ms,
                "headers": resp_headers,
                "cookies": resp.cookies.get_dict(),
                "forms": forms,
                "outbound_links": len(discovered_links),
                "error": None
            })

        except Exception as ex:
            records.append({
                "url": target,
                "status": "ERR",
                "latency_ms": 0,
                "headers": {},
                "cookies": {},
                "forms": [],
                "outbound_links": 0,
                "error": str(ex)
            })

    return records

def audit_page_vulnerabilities(record: dict) -> list:
    """
    Applies deterministic security rules to detect standard misconfigurations
    and security posture weaknesses without offensive exploitation.
    """
    url = record["url"]
    headers = {k.lower(): v for k, v in record["headers"].items()}
    forms = record["forms"]
    issues = []

    # 1. Transport Layer Security (OWASP A02:2021 / CWE-319)
    if url.startswith("http://"):
        issues.append({
            "owasp": "A02:2021 - Cryptographic Failures",
            "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
            "severity": "High",
            "component": url,
            "evidence": f"Endpoint serves content over unencrypted HTTP protocol.",
            "impact": "Network observers can intercept, view, and alter traffic in transit.",
            "fix": "Redirect all port 80 traffic to port 443 with a 301 Permanent Redirect.",
            "config": """server {
    listen 80;
    server_name example.com *.example.com;
    return 301 https://$host$request_uri;
}"""
        })

    # 2. Strict Transport Security (HSTS - RFC 6797 / CWE-523)
    if "strict-transport-security" not in headers:
        issues.append({
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-523: Unprotected Transport Sports",
            "severity": "High",
            "component": f"Header on {url}",
            "evidence": "Strict-Transport-Security header was omitted from the server response.",
            "impact": "Clients may initiate the first connection unencrypted, leaving users vulnerable to SSL-stripping.",
            "fix": "Enforce HSTS across the primary domain and all subdomains for at least 1 year.",
            "config": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;"
        })

    # 3. Content Security Policy (W3C CSP / CWE-1021 / CWE-79)
    if "content-security-policy" not in headers:
        issues.append({
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-1021: Improper Restriction of Rendered UI Layers",
            "severity": "Medium",
            "component": f"Header on {url}",
            "evidence": "No Content-Security-Policy (CSP) header defined.",
            "impact": "Absence of resource origin restrictions increases vulnerability to Cross-Site Scripting (XSS) and framing attacks.",
            "fix": "Define a restrictive Content-Security-Policy disallowing untrusted third-party scripts and disallowing frame embedding.",
            "config": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; frame-ancestors 'none'; object-src 'none';\" always;"
        })

    # 4. MIME-Type Sniffing Protection (RFC 7231 / CWE-79)
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        issues.append({
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation",
            "severity": "Low",
            "component": f"Header on {url}",
            "evidence": f"X-Content-Type-Options is missing or not set to 'nosniff' (Observed: '{headers.get('x-content-type-options', 'None')}').",
            "impact": "Browsers may execute non-executable files if they infer the MIME type differs from the declared header.",
            "fix": "Instruct browsers to strictly adhere to declared MIME types.",
            "config": "add_header X-Content-Type-Options \"nosniff\" always;"
        })

    # 5. Form Credential Handling (OWASP A04:2021 / CWE-598)
    for form in forms:
        inputs = [str(item["name"]).lower() for item in form["inputs"]]
        cred_fields = [f for f in inputs if any(k in f for k in ["pass", "token", "key", "secret", "cvv"])]
        
        if form["method"] == "GET" and cred_fields:
            issues.append({
                "owasp": "A04:2021 - Insecure Design",
                "cwe": "CWE-598: Use of GET Request Method With Sensitive Query Strings",
                "severity": "High",
                "component": f"Form #{form['id']} on {url} (action: '{form['action']}')",
                "evidence": f"Form accepts sensitive field(s) {cred_fields} but transmits via HTTP GET.",
                "impact": "Credentials are appended to URLs and get permanently stored in proxy logs, browser histories, and Referer headers.",
                "fix": "Change form transmission method to POST and handle authorization tokens in secure request bodies.",
                "config": """<!-- Compliant Form Specification -->
<form action="/login" method="POST" autocomplete="off">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
    <input type="password" name="password" required />
    <button type="submit">Sign In</button>
</form>"""
            })

    return issues

# ----------------- UI INTERFACE -----------------

st.title("🖥️ CRT CYBER SQUAD — VAPT AUDIT CONSOLE")
st.caption("Non-Offensive, Evidence-Grounded Security Posture & Vulnerability Assessment Platform")

with st.sidebar:
    st.header("⚙️ Audit Parameters")
    target_url = st.text_input("Target Root URL:", value="https://example.com")
    crawl_limit = st.slider("Max Crawl Depth (Pages):", min_value=3, max_value=25, value=8)
    include_subdomains = st.checkbox("Audit Subdomains", value=True)
    launch_btn = st.button("🚀 Run Vulnerability Audit", type="primary", use_container_width=True)

# 2x2 Agent HUD Console
agent_hud = st.empty()

def render_agent_hud(agents):
    html = f"""
    <div class="agent-grid">
        <div class="agent-card">
            <div class="agent-title">
                <span>[AGENT 1] RECON ROVER</span>
                <span class="{agents['rover']['badge']}">{agents['rover']['status']}</span>
            </div>
            <div class="agent-screen">{agents['rover']['msg']}</div>
        </div>
        <div class="agent-card">
            <div class="agent-title">
                <span>[AGENT 2] ARCHITECTURE AUDITOR</span>
                <span class="{agents['auditor']['badge']}">{agents['auditor']['status']}</span>
            </div>
            <div class="agent-screen">{agents['auditor']['msg']}</div>
        </div>
        <div class="agent-card">
            <div class="agent-title">
                <span>[AGENT 3] INPUT INSPECTOR</span>
                <span class="{agents['inspector']['badge']}">{agents['inspector']['status']}</span>
            </div>
            <div class="agent-screen">{agents['inspector']['msg']}</div>
        </div>
        <div class="agent-card">
            <div class="agent-title">
                <span>[AGENT 4] REMEDIATION COUNSELOR</span>
                <span class="{agents['counselor']['badge']}">{agents['counselor']['status']}</span>
            </div>
            <div class="agent-screen">{agents['counselor']['msg']}</div>
        </div>
    </div>
    """
    agent_hud.markdown(html, unsafe_allow_html=True)

agents = {
    "rover": {"status": "STANDBY", "badge": "badge-idle", "msg": "Awaiting scope parameters..."},
    "auditor": {"status": "STANDBY", "badge": "badge-idle", "msg": "Protocol & header rules ready."},
    "inspector": {"status": "STANDBY", "badge": "badge-idle", "msg": "Form schema analyzer armed."},
    "counselor": {"status": "STANDBY", "badge": "badge-idle", "msg": "CWE remediation repository loaded."}
}
render_agent_hud(agents)

if launch_btn:
    if not target_url.startswith(("http://", "https://")):
        st.error("Please supply a valid URL scheme (e.g., https://example.com)")
    else:
        # Step 1: Recon & Crawling
        agents["rover"] = {"status": "CRAWLING", "badge": "badge-active", "msg": f"Traversing routes & subdomains across {target_url}..."}
        render_agent_hud(agents)
        
        crawl_data = execute_deterministic_crawl(target_url, max_pages=crawl_limit, scan_subdomains=include_subdomains)
        
        agents["rover"] = {"status": "COMPLETE", "badge": "badge-active", "msg": f"Indexed {len(crawl_data)} scoped endpoints."}
        agents["auditor"] = {"status": "AUDITING", "badge": "badge-active", "msg": "Verifying transport layers and HTTP response headers..."}
        agents["inspector"] = {"status": "AUDITING", "badge": "badge-active", "msg": "Inspecting HTML forms and input validation semantics..."}
        render_agent_hud(agents)

        # Step 2: Assessment
        all_findings = []
        for record in crawl_data:
            if not record["error"]:
                all_findings.extend(audit_page_vulnerabilities(record))

        agents["auditor"] = {"status": "COMPLETE", "badge": "badge-active", "msg": "Cryptographic and configuration analysis completed."}
        agents["inspector"] = {"status": "COMPLETE", "badge": "badge-active", "msg": "Input parameters analyzed against CWE-598."}
        agents["counselor"] = {"status": "COMPLETE", "badge": "badge-active", "msg": f"Mapped {len(all_findings)} issues to verified remediations."}
        render_agent_hud(agents)

        st.markdown("---")

        # ----------------- SECTION 1: CRAWL & TELEMETRY LEDGER -----------------
        st.subheader("📑 1. Crawl Scope & Endpoint Telemetry")
        st.caption("Deterministic breakdown of each crawled resource, response latency, and discovered assets:")

        ledger_rows = []
        for r in crawl_data:
            ledger_rows.append({
                "Target Endpoint": r["url"],
                "HTTP Status": str(r["status"]),
                "Latency": f"{r['latency_ms']} ms",
                "Forms Detected": len(r["forms"]),
                "Outbound Links": r["outbound_links"]
            })
        st.dataframe(ledger_rows, use_container_width=True)

        # ----------------- SECTION 2: VULNERABILITY AUDIT -----------------
        st.subheader("🛡️ 2. Identified Vulnerabilities & Hardening Guidelines")
        st.caption("Every finding is substantiated with exact server telemetry and direct remediation blocks.")

        if not all_findings:
            st.success("Audit complete: No security misconfigurations or architectural weaknesses identified under current rules.")
        else:
            for item in all_findings:
                sev_lower = item["severity"].lower()
                st.markdown(f"""
                <div class="vuln-card {sev_lower}">
                    <span style="font-size:11px; font-weight:bold; color:#555;">{item['owasp']} | {item['cwe']}</span>
                    <h3 style="margin: 4px 0 8px 0;">{item['cwe'].split(':')[1] if ':' in item['cwe'] else item['cwe']} 
                        <span style="font-size:12px; text-transform:uppercase;">[{item['severity']} Severity]</span>
                    </h3>
                    <p style="margin:2px 0;"><b>Affected Component:</b> <code>{item['component']}</code></p>
                    <div class="evidence-block">
                        <b>Deterministic Evidence:</b> {item['evidence']}
                    </div>
                    <p style="margin:4px 0;"><b>Security Impact:</b> {item['impact']}</p>
                    <div class="remediation-block">
                        <b>Remediation Directive:</b> {item['fix']}
                        <div style="margin-top:6px;">
                            <b>Hardening Reference:</b>
                            <pre class="code-snippet">{item['config']}</pre>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)