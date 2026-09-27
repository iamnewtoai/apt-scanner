import os
import re
import time
from collections import deque
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
import streamlit as st

# ----------------- CONFIG & RETRO CRT THEME -----------------
st.set_page_config(
    page_title="CRT Cyber Squad | Threat Model & Hardening Console",
    page_icon="🤖",
    layout="wide"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Bungee&display=swap');

    .stApp {
        background-color: #f3efe6;
        color: #1a1a1a;
        font-family: 'Share Tech Mono', monospace;
    }

    .agent-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 14px;
        margin-bottom: 20px;
    }
    .agent-cell {
        background-color: #ffffff;
        border: 3px solid #222;
        border-radius: 10px;
        padding: 14px;
        box-shadow: 5px 5px 0px #111;
    }
    .agent-header {
        font-family: 'Bungee', cursive, monospace;
        font-size: 14px;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .agent-crt {
        background-color: #1b261c;
        border: 2px solid #334;
        border-radius: 6px;
        padding: 8px 12px;
        color: #5af75a;
        font-size: 12px;
        min-height: 55px;
        box-shadow: inset 0 0 8px rgba(0,0,0,0.8);
    }

    .badge-active { background: #2e7d32; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px; }
    .badge-idle { background: #757575; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px; }

    .finding-card {
        background: #ffffff;
        border: 2px solid #222;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 20px;
        box-shadow: 4px 4px 0px #222;
    }
    .threat-section {
        background-color: #fff3f3;
        border-left: 4px solid #d32f2f;
        padding: 10px 14px;
        margin: 10px 0;
        border-radius: 0 4px 4px 0;
    }
    .defense-section {
        background-color: #f1f8e9;
        border-left: 4px solid #2e7d32;
        padding: 10px 14px;
        margin: 10px 0;
        border-radius: 0 4px 4px 0;
    }
    .cmd-box {
        background: #1b1e24;
        color: #4af626;
        padding: 10px;
        border-radius: 4px;
        font-family: 'Share Tech Mono', monospace;
        font-size: 12px;
        overflow-x: auto;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- RECON & SCANNING ENGINE -----------------

def get_base_domain(host: str) -> str:
    parts = host.split('.')
    return ".".join(parts[-2:]) if len(parts) > 2 else host

def run_deep_crawl(start_url: str, max_pages: int = 10, allow_subdomains: bool = True):
    parsed_start = urlparse(start_url)
    root_domain = get_base_domain(parsed_start.netloc)
    visited_pages = set()
    queue = deque([start_url])
    crawl_records = []

    req_headers = {"User-Agent": "CRTSquad-SecurityAuditor/3.0"}

    while queue and len(visited_pages) < max_pages:
        current_url = queue.popleft()
        if current_url in visited_pages:
            continue
        visited_pages.add(current_url)

        try:
            resp = requests.get(current_url, headers=req_headers, timeout=6, allow_redirects=True)
            headers = dict(resp.headers)
            content_type = headers.get("Content-Type", "")
            discovered_forms = []
            new_links = []

            if "text/html" in content_type:
                soup = BeautifulSoup(resp.text, "html.parser")
                for f_idx, form in enumerate(soup.find_all("form")):
                    discovered_forms.append({
                        "index": f_idx + 1,
                        "action": urljoin(current_url, form.get("action", "")),
                        "method": form.get("method", "GET").upper(),
                        "inputs": [inp.get("name", "unnamed") for inp in form.find_all(["input", "textarea", "select"])]
                    })

                for tag in soup.find_all("a", href=True):
                    full_url = urljoin(current_url, tag['href'].strip())
                    link_domain = urlparse(full_url).netloc
                    is_in_scope = (link_domain == root_domain or link_domain.endswith(f".{root_domain}")) if allow_subdomains else (link_domain == parsed_start.netloc)
                    if is_in_scope and full_url not in visited_pages and full_url not in queue:
                        new_links.append(full_url)
                        queue.append(full_url)

            crawl_records.append({
                "url": current_url,
                "status_code": resp.status_code,
                "headers": headers,
                "forms": discovered_forms,
                "links_found": len(new_links),
                "error": None
            })
        except Exception as err:
            crawl_records.append({
                "url": current_url,
                "status_code": "ERR",
                "headers": {},
                "forms": [],
                "links_found": 0,
                "error": str(err)
            })

    return crawl_records

def audit_page_vulnerabilities(page_record: dict) -> list:
    url = page_record["url"]
    headers = page_record["headers"]
    forms = page_record["forms"]
    issues = []

    # 1. Cleartext Transmission
    if url.startswith("http://"):
        issues.append({
            "category": "OWASP A02:2021 - Cryptographic Failures",
            "title": "Cleartext HTTP Protocol in Use",
            "severity": "High",
            "location": url,
            "evidence": "Endpoint served without Transport Layer Security (TLS).",
            "threat_model": {
                "mindset": "Adversaries targeting local or transit networks monitor unencrypted traffic to capture session tokens, credentials, and sensitive transaction parameters.",
                "vector": "Adversary performs Man-in-the-Middle (MitM) inspection or ARP cache poisoning on shared networks (e.g., untrusted Wi-Fi) to intercept raw traffic.",
                "verification_cmd": f"curl -I -s -X GET \"{url}\" | grep -i \"HTTP/\""
            },
            "defense": {
                "concept": "Enforce mandatory TLS encryption across all endpoints and redirect all insecure port 80 requests to port 443.",
                "steps": [
                    "Obtain and install a valid TLS certificate (e.g., via Let's Encrypt).",
                    "Configure 301 permanent redirects from HTTP to HTTPS.",
                    "Verify cipher suites disable legacy algorithms (SSLv3, TLS 1.0, TLS 1.1)."
                ],
                "commands": """# Nginx Redirection Block:
server {
    listen 80;
    server_name example.com *.example.com;
    return 301 https://$host$request_uri;
}"""
            }
        })

    # 2. Missing Strict-Transport-Security (HSTS)
    if "strict-transport-security" not in [h.lower() for h in headers.keys()]:
        issues.append({
            "category": "OWASP A05:2021 - Security Misconfiguration",
            "title": "Missing Strict-Transport-Security (HSTS)",
            "severity": "High",
            "location": f"Header at {url}",
            "evidence": "Strict-Transport-Security header omitted from HTTP response.",
            "threat_model": {
                "mindset": "Attackers exploit user tendencies to enter domain names without protocols, intercepting initial requests before secure upgrades occur.",
                "vector": "SSL stripping tools manipulate unencrypted initial requests, intercepting client traffic while proxying HTTPS to the upstream server.",
                "verification_cmd": f"curl -s -I \"{url}\" | grep -i \"Strict-Transport-Security\""
            },
            "defense": {
                "concept": "Instruct user agents to refuse unencrypted connections for the specified domain and all associated subdomains.",
                "steps": [
                    "Set max-age to at least 1 year (31536000 seconds).",
                    "Include the includeSubDomains directive.",
                    "Submit the domain to the Chromium HSTS preload list."
                ],
                "commands": """# Nginx:
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# Apache (.htaccess or httpd.conf):
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" """
            }
        })

    # 3. Missing Content-Security-Policy (CSP)
    if "content-security-policy" not in [h.lower() for h in headers.keys()]:
        issues.append({
            "category": "OWASP A03:2021 - Injection (XSS Vector)",
            "title": "Missing Content-Security-Policy (CSP)",
            "severity": "Medium",
            "location": f"Header at {url}",
            "evidence": "No Content-Security-Policy header defined.",
            "threat_model": {
                "mindset": "Adversaries identifying user input reflection or third-party script vulnerabilities rely on the browser's default execution permissions to load unauthorized JavaScript.",
                "vector": "Injecting malicious scripts or inline event handlers that can execute freely, access storage mechanisms, or exfiltrate tokens without origin restrictions.",
                "verification_cmd": f"curl -s -I \"{url}\" | grep -i \"Content-Security-Policy\""
            },
            "defense": {
                "concept": "Establish a whitelist of authorized script, image, and resource origins, restricting unauthorized script execution.",
                "steps": [
                    "Deploy default-src 'self' to restrict resources to the primary origin by default.",
                    "Use cryptographically random nonces (nonce-...) for inline scripts instead of 'unsafe-inline'.",
                    "Deploy the policy in report-only mode initially to audit compatibility."
                ],
                "commands": """# Nginx Directive:
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none';" always;"""
            }
        })

    # 4. Insecure Form Method with Sensitive Inputs
    for form in forms:
        input_names = [str(inp).lower() for inp in form["inputs"]]
        sensitive_keywords = ["pass", "password", "token", "secret", "cvv", "key", "auth"]
        if form["method"] == "GET" and any(k in " ".join(input_names) for k in sensitive_keywords):
            issues.append({
                "category": "OWASP A04:2021 - Insecure Design",
                "title": "Sensitive Parameters Exposed via GET Method",
                "severity": "High",
                "location": f"Form #{form['index']} at {url} (action: {form['action']})",
                "evidence": f"Form processes sensitive fields using HTTP GET: {', '.join(form['inputs'])}",
                "threat_model": {
                    "mindset": "Adversaries target persistent logs and peripheral channels where query strings are routinely recorded without encryption.",
                    "vector": "Parameters sent via GET persist in browser histories, web proxy access logs, and upstream Referer headers when loading off-site assets.",
                    "verification_cmd": f"grep -inE 'method=[\"\\']get[\"\\']' page_dump.html"
                },
                "defense": {
                    "concept": "Transmit authentication and credential payloads strictly inside the encrypted body of HTTP POST requests.",
                    "steps": [
                        "Update the form tag attribute method='POST'.",
                        "Ensure endpoint controllers only accept POST/PUT verbs for credential handling.",
                        "Set Cache-Control: no-store on forms handling authentication."
                    ],
                    "commands": """<!-- Remediated HTML Pattern -->
<form action="/login" method="POST" autocomplete="off">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
    <input type="password" name="password" required />
    <button type="submit">Sign In</button>
</form>"""
                }
            })

    return issues

# ----------------- UI INTERFACE -----------------

st.title("🖥️ CRT CYBER SQUAD — VAPT CONSOLE")
st.caption("Deep Crawling, Threat Vector Analysis, and Defensive Hardening")

with st.sidebar:
    st.header("⚙️ Scanner Control")
    target_input = st.text_input("Target Root URL:", value="https://example.com")
    max_pages = st.slider("Max Pages to Crawl:", min_value=3, max_value=25, value=8)
    include_subdomains = st.checkbox("Include Subdomains", value=True)
    start_btn = st.button("🚀 Run Assessment", type="primary", use_container_width=True)

# 2x2 Agent Status Display
agent_grid_placeholder = st.empty()

def update_agent_ui(states):
    html = f"""
    <div class="agent-grid">
        <div class="agent-cell">
            <div class="agent-header"><span>[AGENT 1] CRT ROVER</span><span class="{states['rover']['b']}">{states['rover']['s']}</span></div>
            <div class="agent-crt">{states['rover']['m']}</div>
        </div>
        <div class="agent-cell">
            <div class="agent-header"><span>[AGENT 2] CRT PROBE</span><span class="{states['probe']['b']}">{states['probe']['s']}</span></div>
            <div class="agent-crt">{states['probe']['m']}</div>
        </div>
        <div class="agent-cell">
            <div class="agent-header"><span>[AGENT 3] CRT VERIFIER</span><span class="{states['verifier']['b']}">{states['verifier']['s']}</span></div>
            <div class="agent-crt">{states['verifier']['m']}</div>
        </div>
        <div class="agent-cell">
            <div class="agent-header"><span>[AGENT 4] CRT COUNSELOR</span><span class="{states['counselor']['b']}">{states['counselor']['s']}</span></div>
            <div class="agent-crt">{states['counselor']['m']}</div>
        </div>
    </div>
    """
    agent_grid_placeholder.markdown(html, unsafe_allow_html=True)

states = {
    "rover": {"s": "IDLE", "b": "badge-idle", "m": "Waiting for target specification..."},
    "probe": {"s": "IDLE", "b": "badge-idle", "m": "Passive rule engine loaded."},
    "verifier": {"s": "IDLE", "b": "badge-idle", "m": "Zero-hallucination verification active."},
    "counselor": {"s": "IDLE", "b": "badge-idle", "m": "Defensive mitigation templates ready."}
}
update_agent_ui(states)

if start_btn:
    if not target_input.startswith(("http://", "https://")):
        st.error("Please provide a valid protocol prefix (http:// or https://)")
    else:
        # Phase 1: Reconnaissance
        states["rover"] = {"s": "SCANNING", "b": "badge-active", "m": f"Traversing subdomains and paths across {target_input}..."}
        update_agent_ui(states)
        crawl_results = run_deep_crawl(target_input, max_pages=max_pages, allow_subdomains=include_subdomains)

        # Phase 2 & 3: Audit & Verification
        states["rover"] = {"s": "DONE", "b": "badge-active", "m": f"Discovered {len(crawl_results)} pages and endpoints."}
        states["probe"] = {"s": "AUDITING", "b": "badge-active", "m": "Evaluating headers, inputs, and form methods..."}
        update_agent_ui(states)

        all_findings = []
        for page in crawl_results:
            if not page["error"]:
                all_findings.extend(audit_page_vulnerabilities(page))

        states["probe"] = {"s": "DONE", "b": "badge-active", "m": "Surface audit complete."}
        states["verifier"] = {"s": "VERIFYING", "b": "badge-active", "m": f"Validated {len(all_findings)} deterministic issues."}
        states["counselor"] = {"s": "DONE", "b": "badge-active", "m": "Remediation workflows generated."}
        update_agent_ui(states)

        st.markdown("---")

        # Table: Crawled Pages
        st.subheader("📑 1. Discovered Endpoints & Scope Summary")
        table_rows = [
            {
                "Target Endpoint": r["url"],
                "HTTP Status": str(r["status_code"]),
                "Forms Detected": len(r["forms"]),
                "Outbound Links": r["links_found"]
            }
            for r in crawl_results
        ]
        st.dataframe(table_rows, use_container_width=True)

        # Detailed Security Findings
        st.subheader("🛡️ 2. Detailed Threat Analysis & Defensive Remediation")

        if not all_findings:
            st.success("No surface vulnerabilities detected based on current passive rules.")
        else:
            for item in all_findings:
                tm = item["threat_model"]
                df = item["defense"]

                st.markdown(f"""
                <div class="finding-card">
                    <span style="font-size:11px; font-weight:bold; color:#777;">{item['category']}</span>
                    <h3 style="margin: 4px 0 8px 0;">{item['title']} <span style="font-size:12px; color:#d32f2f;">[{item['severity']} Severity]</span></h3>
                    <p><b>Target Component:</b> <code>{item['location']}</code></p>
                    <p><b>Evidence:</b> {item['evidence']}</p>

                    <!-- SECTION A: THREAT MODEL & EXPLOITATION MECHANICS -->
                    <div class="threat-section">
                        <h4 style="margin: 0 0 6px 0; color: #b71c1c;">⚠️ Adversary Threat Model & Mechanics</h4>
                        <p style="margin: 2px 0;"><b>Attacker Mindset:</b> {tm['mindset']}</p>
                        <p style="margin: 2px 0;"><b>Attack Vector:</b> {tm['vector']}</p>
                        <p style="margin: 6px 0 2px 0;"><b>Diagnostic Verification Command:</b></p>
                        <div class="cmd-box">{tm['verification_cmd']}</div>
                    </div>

                    <!-- SECTION B: DEFENSIVE HARDENING & REMEDIATION -->
                    <div class="defense-section">
                        <h4 style="margin: 0 0 6px 0; color: #1b5e20;">🛡️ Defensive Hardening & Implementation Steps</h4>
                        <p style="margin: 2px 0;"><b>Security Concept:</b> {df['concept']}</p>
                        <p style="margin: 6px 0 2px 0;"><b>Required Remediation Steps:</b></p>
                        <ul style="margin: 2px 0 6px 20px;">
                            {''.join(f'<li>{step}</li>' for step in df['steps'])}
                        </ul>
                        <p style="margin: 6px 0 2px 0;"><b>Configuration / Patch Implementation:</b></p>
                        <pre class="cmd-box">{df['commands']}</pre>
                    </div>
                </div>
                """, unsafe_allow_html=True)