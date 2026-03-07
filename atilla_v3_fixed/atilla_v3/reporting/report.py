import json
from datetime import datetime
from typing import Dict, List
from colorama import Fore
from core.config import ScanConfig
from core.models import Vulnerability, Severity


class ReportManager:
    def __init__(self, config: ScanConfig, vulns: List[Vulnerability]):
        self.config = config
        self.vulns  = vulns

    def print_summary(self):
        print(f"\n{Fore.CYAN}{'='*65}")
        print(f"{Fore.CYAN} SCAN COMPLETE — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}{'='*65}")
        if not self.vulns:
            print(f"{Fore.GREEN}\n[+] No high-confidence vulnerabilities detected.")
            return
        by_sev: Dict[str, List[Vulnerability]] = {}
        for v in self.vulns:
            by_sev.setdefault(v.severity.value, []).append(v)
        print(f"\n{Fore.RED}[!] {len(self.vulns)} potential vulnerabilities:\n")
        for sev in [Severity.CRITICAL.value, Severity.HIGH.value,
                    Severity.MEDIUM.value, Severity.LOW.value]:
            group = by_sev.get(sev, [])
            if not group: continue
            col = group[0].color()
            print(f"{col}  {sev}: {len(group)}")
            for v in group:
                cvss_s = f"  CVSS {v.cvss.base_score}" if v.cvss else ""
                print(f"{col}    [{v.confidence}%{cvss_s}] {v.param} <- {v.payload[:60]}")
                print(f"{col}      {v.url[:100]}")

    def _report_dict(self) -> dict:
        counts: Dict[str, int] = {}
        for v in self.vulns:
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        return {
            "tool": "ATILLA v3.0", "scan_time": datetime.now().isoformat(),
            "target_url": self.config.url, "payload_set": self.config.payload_set,
            "waf_detected": self.config.detected_waf,
            "total_findings": len(self.vulns), "severity_summary": counts,
            "findings": [v.to_dict() for v in self.vulns],
        }

    def save_json(self, filename: str):
        try:
            with open(filename, "w") as f:
                json.dump(self._report_dict(), f, indent=2, default=str)
            print(f"\n{Fore.GREEN}[+] JSON report -> {filename}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] JSON save failed: {e}")

    def save_html(self, filename: str):
        r      = self._report_dict()
        sev_cl = {"CRITICAL":"#e74c3c","HIGH":"#e67e22","MEDIUM":"#f1c40f","LOW":"#3498db"}
        findings_html = ""
        summary_cards = "".join(
            "<div class='stat'><div class='n' style='color:{}'>{}</div><div class='l'>{}</div></div>".format(
                sev_cl.get(s, "#95a5a6"), c, s
            )
            for s, c in r['severity_summary'].items()
        )
        for f in r["findings"]:
            c    = sev_cl.get(f["severity"], "#95a5a6")
            dets = "".join(f"<li>{d}</li>" for d in f.get("details", []))
            snks = "".join(f"<li>{s}</li>" for s in f.get("dom_sinks", []))
            cvss = (f'<span class="badge" style="background:{c}">'
                    f'{f["cvss"]["base_score"]} {f["cvss"]["rating"]}</span>'
                    if f.get("cvss") else "")
            findings_html += f"""
            <div class="card">
              <div class="fh" style="border-left:4px solid {c}">
                <b style="color:{c}">{f['severity']}</b>
                <span>{f['confidence']}% confidence</span>
                {cvss}
                <span>ctx: {f['context']}</span>
              </div>
              <table>
                <tr><th>Param</th><td><code>{f['param']}</code></td></tr>
                <tr><th>URL</th><td><code>{f['url'][:120]}</code></td></tr>
                <tr><th>Payload</th><td><code>{f['payload'][:120]}</code></td></tr>
                <tr><th>Status</th><td>{f['status_code']} / {f['response_length']} bytes</td></tr>
              </table>
              {"<h4>Details</h4><ul>"+dets+"</ul>" if dets else ""}
              {"<h4>DOM Sinks</h4><ul>"+snks+"</ul>" if snks else ""}
              {"<h4>Evidence</h4><pre>"+f['evidence'][:300]+"</pre>" if f.get('evidence') else ""}
            </div>"""
        body = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>ATILLA Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:2rem}}
h1{{color:#00ff41;margin-bottom:.5rem}}h2{{color:#58a6ff;margin:1.5rem 0 .5rem}}
.meta{{color:#8b949e;font-size:.9rem;margin-bottom:1rem}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:1rem;margin:1rem 0}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;text-align:center}}
.stat .n{{font-size:2rem;font-weight:bold;color:#00ff41}}.stat .l{{font-size:.8rem;color:#8b949e}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin:.75rem 0;padding:1rem}}
.fh{{display:flex;gap:1rem;align-items:center;margin-bottom:.75rem;flex-wrap:wrap}}
.badge{{padding:.2rem .5rem;border-radius:4px;color:#fff;font-size:.75rem;font-weight:bold}}
table{{width:100%;border-collapse:collapse;font-size:.85rem;margin:.5rem 0}}
th{{color:#8b949e;padding:.3rem .5rem;text-align:left;width:110px}}
td{{padding:.3rem .5rem;word-break:break-all}}
code{{background:#0d1117;padding:.1rem .3rem;border-radius:3px;font-family:monospace;font-size:.82rem}}
pre{{background:#0d1117;padding:.75rem;border-radius:6px;overflow-x:auto;font-size:.8rem;margin:.25rem 0}}
h4{{color:#8b949e;font-size:.85rem;margin:.5rem 0}}ul{{padding-left:1.2rem;font-size:.85rem}}
footer{{margin-top:2rem;font-size:.8rem;color:#484f58;text-align:center}}
</style></head><body>
<h1>&#9876; ATILLA v3.0 — XSS Report</h1>
<div class="meta">Target: <b>{r['target_url']}</b> &nbsp;|&nbsp; {r['scan_time']}
{' &nbsp;|&nbsp; WAF: <b>'+r['waf_detected']+'</b>' if r['waf_detected'] else ''}</div>
<h2>Summary</h2>
<div class="grid">
  <div class="stat"><div class="n">{r['total_findings']}</div><div class="l">TOTAL</div></div>
  {summary_cards}
</div>
<h2>Findings</h2>
{findings_html or "<p style='color:#8b949e'>No findings.</p>"}
<footer>ATILLA v3.0 — Authorized security testing only</footer>
</body></html>"""
        try:
            with open(filename, "w") as fh: fh.write(body)
            print(f"\n{Fore.GREEN}[+] HTML report -> {filename}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] HTML save failed: {e}")
