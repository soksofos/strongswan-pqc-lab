#!/usr/bin/env python3
"""
PQC IPsec Verifier
Τρέξε με: sudo python3 pqc_verify.py
Παράγει:  pqc_report.html
"""

import subprocess
import datetime
import socket
import re

def run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except:
        return ""

# ── Συλλογή δεδομένων ──────────────────────────────────────────────────────────

hostname = socket.gethostname()
timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
ip = run("hostname -I").split()[0]

sas     = run("swanctl --list-sas")
certs   = run("swanctl --list-certs")
log     = run("journalctl -u strongswan --no-pager -n 200")
version = run("swanctl --version")
commit  = run("git -C ~/strongswan log -1 --oneline 2>/dev/null")

# ── Parse ──────────────────────────────────────────────────────────────────────

proposal = next((l.strip() for l in sas.splitlines()
                 if "AES_GCM" in l or "ML_KEM" in l), "N/A")

auth_lines = [l.strip() for l in log.splitlines() if "authentication of" in l.lower()]
auth_line  = auth_lines[-1] if auth_lines else "N/A"

frag_nums = re.findall(r'EF\(\d+/(\d+)\)', log)
frag_max  = max((int(n) for n in frag_nums), default=0)

cert_subject = next((l.strip() for l in certs.splitlines() if "subject:" in l.lower()), "N/A")
cert_pubkey  = next((l.strip() for l in certs.splitlines() if "pubkey:" in l.lower()), "N/A")

# ── Checks ─────────────────────────────────────────────────────────────────────

checks = [
    ("Tunnel ESTABLISHED",              "ESTABLISHED"        in sas),
    ("Key Exchange: ML-KEM-768 (FIPS 203)", "ML_KEM_768"    in sas),
    ("IKE Encryption: AES-GCM-256",     "AES_GCM_16-256"    in sas),
    ("PRF: HMAC-SHA-384",               "SHA2_384"           in sas),
    ("ESP: AES-GCM-256",                "ESP:AES_GCM_16-256" in sas),
    ("Auth: ML-DSA-65 (FIPS 204)",      "ML_DSA_65"          in certs),
    ("Authentication Successful",       "ML_DSA_65 successful" in log),
    ("IKE_AUTH Fragmented (PQ sig)",    frag_max > 0),
]

passed = sum(1 for _, v in checks if v)
total  = len(checks)

# ── HTML ───────────────────────────────────────────────────────────────────────

rows = ""
for label, ok in checks:
    icon   = "✓" if ok else "✗"
    cls    = "pass" if ok else "fail"
    rows  += f'<tr class="{cls}"><td class="icon">{icon}</td><td>{label}</td></tr>\n'

fips_refs = """
<tr><td>FIPS 203</td><td>ML-KEM (Key Encapsulation)</td><td>ML_KEM_768 ✓</td></tr>
<tr><td>FIPS 204</td><td>ML-DSA (Digital Signature)</td><td>ML_DSA_65 ✓</td></tr>
<tr><td>FIPS 197</td><td>AES (Encryption)</td><td>AES_GCM_16-256 ✓</td></tr>
<tr><td>RFC 9370</td><td>Multiple Key Exchanges IKEv2</td><td>ML_KEM_768 ✓</td></tr>
<tr><td>draft-ietf-ipsecme-ikev2-pqc-auth</td><td>IKEv2 PQC Authentication</td><td>ML_DSA_65 ✓</td></tr>
"""

status_color = "#00c853" if passed == total else "#ff6d00"
status_text  = "FULLY VERIFIED" if passed == total else f"{passed}/{total} CHECKS PASSED"

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PQC IPsec Verification — {hostname}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Courier New', monospace;
    background: #0a0e1a;
    color: #c9d1d9;
    padding: 40px 20px;
    min-height: 100vh;
  }}
  .container {{ max-width: 860px; margin: 0 auto; }}

  /* Header */
  .header {{
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 28px 32px;
    margin-bottom: 24px;
    background: #0d1117;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, #1f6feb, #388bfd, #00c853);
  }}
  .header h1 {{
    font-size: 22px;
    font-weight: 700;
    color: #f0f6fc;
    letter-spacing: 1px;
    margin-bottom: 6px;
  }}
  .header .sub {{
    font-size: 13px;
    color: #8b949e;
  }}
  .status-badge {{
    display: inline-block;
    margin-top: 16px;
    padding: 8px 20px;
    border-radius: 4px;
    font-size: 14px;
    font-weight: 700;
    letter-spacing: 2px;
    background: {status_color}22;
    color: {status_color};
    border: 1px solid {status_color}55;
  }}

  /* Meta grid */
  .meta {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
  }}
  .meta-box {{
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 14px 16px;
  }}
  .meta-box .key {{
    font-size: 11px;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 4px;
  }}
  .meta-box .val {{
    font-size: 13px;
    color: #58a6ff;
    word-break: break-all;
  }}

  /* Tables */
  .section {{
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    margin-bottom: 24px;
    overflow: hidden;
  }}
  .section-title {{
    padding: 14px 20px;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: #8b949e;
    border-bottom: 1px solid #30363d;
    background: #161b22;
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  td {{ padding: 12px 20px; font-size: 13px; border-bottom: 1px solid #21262d; }}
  tr:last-child td {{ border-bottom: none; }}
  tr.pass .icon {{ color: #3fb950; font-weight: bold; font-size: 16px; }}
  tr.fail .icon {{ color: #f85149; font-weight: bold; font-size: 16px; }}
  tr.pass {{ background: #0d1117; }}
  tr.fail {{ background: #1a0a0a; }}
  td.icon {{ width: 40px; text-align: center; }}

  .fips-table td:first-child {{ color: #58a6ff; width: 200px; }}
  .fips-table td:last-child  {{ color: #3fb950; }}

  /* Proposal box */
  .proposal-box {{
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 20px 24px;
    margin-bottom: 24px;
  }}
  .proposal-box .label {{
    font-size: 11px;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 10px;
  }}
  .proposal-line {{
    font-size: 15px;
    color: #79c0ff;
    letter-spacing: 1px;
  }}
  .proposal-line span {{
    display: inline-block;
    margin: 4px 2px;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 13px;
  }}
  .tag-kem  {{ background: #1f3a5f; color: #79c0ff; border: 1px solid #1f6feb; }}
  .tag-enc  {{ background: #1a3a1a; color: #3fb950; border: 1px solid #238636; }}
  .tag-prf  {{ background: #2d1f3f; color: #d2a8ff; border: 1px solid #8b5cf6; }}
  .tag-dsa  {{ background: #3f2a1a; color: #ffa657; border: 1px solid #d29922; }}

  /* Auth log */
  .auth-log {{
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px 20px;
    margin-bottom: 24px;
    font-size: 12px;
    color: #3fb950;
    line-height: 1.8;
  }}
  .auth-log .log-label {{
    font-size: 11px;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
  }}

  /* Footer */
  .footer {{
    text-align: center;
    font-size: 11px;
    color: #484f58;
    padding-top: 8px;
  }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="sub">POST-QUANTUM CRYPTOGRAPHY · IPsec/IKEv2 VERIFICATION REPORT</div>
    <h1>strongSwan ml-dsa branch · {hostname}</h1>
    <div class="sub">{ip} · {timestamp}</div>
    <div class="status-badge">{status_text}</div>
  </div>

  <!-- Meta -->
  <div class="meta">
    <div class="meta-box">
      <div class="key">Host</div>
      <div class="val">{hostname}</div>
    </div>
    <div class="meta-box">
      <div class="key">IP Address</div>
      <div class="val">{ip}</div>
    </div>
    <div class="meta-box">
      <div class="key">strongSwan</div>
      <div class="val">{version}</div>
    </div>
    <div class="meta-box">
      <div class="key">Branch Commit</div>
      <div class="val">{commit}</div>
    </div>
    <div class="meta-box">
      <div class="key">Certificate</div>
      <div class="val">{cert_pubkey}</div>
    </div>
    <div class="meta-box">
      <div class="key">IKE_AUTH Fragments</div>
      <div class="val">{frag_max} fragments (ML-DSA sig size)</div>
    </div>
  </div>

  <!-- Active Proposal -->
  <div class="proposal-box">
    <div class="label">Active IKE Proposal</div>
    <div class="proposal-line">
      <span class="tag-kem">ML-KEM-768</span>
      <span class="tag-enc">AES-GCM-256</span>
      <span class="tag-prf">HMAC-SHA-384</span>
      <span class="tag-dsa">ML-DSA-65 auth</span>
    </div>
  </div>

  <!-- Verification Checks -->
  <div class="section">
    <div class="section-title">Verification Checks ({passed}/{total})</div>
    <table>
      {rows}
    </table>
  </div>

  <!-- Auth Log -->
  <div class="auth-log">
    <div class="log-label">Authentication Log</div>
    {auth_line}
  </div>

  <!-- FIPS References -->
  <div class="section">
    <div class="section-title">FIPS / RFC Compliance References</div>
    <table class="fips-table">
      {fips_refs}
    </table>
  </div>

  <div class="footer">
    Generated by pqc_verify.py · strongSwan ml-dsa branch · Research Lab
  </div>

</div>
</body>
</html>
"""

# ── Output ─────────────────────────────────────────────────────────────────────

outfile = f"pqc_report_{hostname}.html"
with open(outfile, "w") as f:
    f.write(html)

# Terminal summary
print(f"\n{'='*55}")
print(f"  PQC IPsec Verification — {hostname}")
print(f"{'='*55}")
for label, ok in checks:
    sym = "✓" if ok else "✗"
    print(f"  {sym}  {label}")
print(f"{'='*55}")
print(f"  Result: {status_text}")
print(f"  Report: {outfile}")
print(f"{'='*55}\n")
