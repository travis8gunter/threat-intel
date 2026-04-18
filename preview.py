"""
preview.py
Starts a local HTTP server and opens the threat intel data preview in your browser.

Usage:
  python preview.py              # serves output/ on http://localhost:8888
  python preview.py --port 9000  # custom port
"""

import http.server
import os
import socketserver
import sys
import threading
import time
import webbrowser
from pathlib import Path

PORT       = 8888
OUTPUT_DIR = Path("output")
PREVIEW    = OUTPUT_DIR / "preview.html"

# ---------------------------------------------------------------------------
# Write the preview HTML (self-contained, reads JSON via fetch)
# ---------------------------------------------------------------------------

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Threat Intel Preview</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body   { background: #0d1117; color: #e6edf3; font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; padding: 24px; }
  h1     { font-size: 22px; font-weight: 700; margin-bottom: 4px; color: #f0f6fc; }
  h2     { font-size: 15px; font-weight: 600; color: #8b949e; text-transform: uppercase; letter-spacing: .06em; margin: 28px 0 12px; }
  h3     { font-size: 13px; font-weight: 600; color: #8b949e; margin-bottom: 10px; }
  .meta  { color: #8b949e; font-size: 13px; margin-bottom: 28px; }

  .grid  { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px,1fr)); gap: 12px; margin-bottom: 28px; }
  .stat  { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
  .stat .val { font-size: 28px; font-weight: 700; color: #f0f6fc; }
  .stat .lbl { font-size: 12px; color: #8b949e; margin-top: 4px; }

  .section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
  .section-header { padding: 14px 16px; border-bottom: 1px solid #30363d; display: flex; justify-content: space-between; align-items: center; }
  .section-header h3 { margin: 0; color: #f0f6fc; }
  .badge { font-size: 11px; padding: 2px 8px; border-radius: 99px; font-weight: 600; }
  .badge-red    { background: rgba(248,81,73,.15);  color: #f85149; }
  .badge-orange { background: rgba(210,153,34,.15); color: #d29922; }
  .badge-blue   { background: rgba(56,139,253,.15); color: #388bfd; }
  .badge-green  { background: rgba(63,191,122,.15); color: #3fb97a; }
  .badge-purple { background: rgba(168,85,247,.15); color: #a855f7; }
  .badge-gray   { background: rgba(139,148,158,.15);color: #8b949e; }

  table  { width: 100%; border-collapse: collapse; }
  th     { text-align: left; padding: 8px 16px; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: #8b949e; border-bottom: 1px solid #30363d; }
  td     { padding: 10px 16px; border-bottom: 1px solid #21262d; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #1c2129; }

  .sev   { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
  .sev-critical { background: rgba(248,81,73,.2);  color: #f85149; }
  .sev-high     { background: rgba(210,153,34,.2); color: #d29922; }
  .sev-medium   { background: rgba(56,139,253,.2); color: #388bfd; }
  .sev-low      { background: rgba(139,148,158,.2);color: #8b949e; }

  .kev-pill { background: rgba(248,81,73,.15); color: #f85149; font-size: 11px; padding: 2px 7px; border-radius: 4px; font-weight: 600; }
  .src-otx  { background: rgba(56,139,253,.15); color: #388bfd; font-size: 11px; padding: 2px 7px; border-radius: 4px; }
  .src-tf   { background: rgba(168,85,247,.15); color: #a855f7; font-size: 11px; padding: 2px 7px; border-radius: 4px; }
  .src-ab   { background: rgba(63,191,122,.15); color: #3fb97a; font-size: 11px; padding: 2px 7px; border-radius: 4px; }

  .bar-row  { display: flex; align-items: center; gap: 10px; padding: 8px 16px; border-bottom: 1px solid #21262d; }
  .bar-row:last-child { border-bottom: none; }
  .bar-label { width: 180px; flex-shrink: 0; }
  .bar-track { flex: 1; height: 8px; background: #21262d; border-radius: 4px; overflow: hidden; }
  .bar-fill  { height: 100%; border-radius: 4px; }
  .bar-val   { width: 50px; text-align: right; color: #8b949e; font-size: 12px; }

  .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
  .status-active   { background: #3fb97a; }
  .status-dormant  { background: #8b949e; }
  .status-disrupted{ background: #f85149; }

  .tabs { display: flex; gap: 2px; padding: 0 16px; border-bottom: 1px solid #30363d; }
  .tab  { padding: 10px 16px; cursor: pointer; color: #8b949e; font-size: 13px; border-bottom: 2px solid transparent; margin-bottom: -1px; }
  .tab.active { color: #f0f6fc; border-bottom-color: #388bfd; }

  .pane { display: none; }
  .pane.active { display: block; }

  .week-header { padding: 16px; display: flex; gap: 16px; align-items: baseline; border-bottom: 1px solid #30363d; }
  .week-tag    { background: #1c2129; border: 1px solid #30363d; border-radius: 6px; padding: 4px 12px; font-size: 12px; color: #8b949e; }
  .week-period { font-size: 18px; font-weight: 600; color: #f0f6fc; }
</style>
</head>
<body>

<h1>🛡 Threat Intel — Data Preview</h1>
<p class="meta" id="meta">Loading…</p>

<!-- Stats grid -->
<div class="grid" id="stats-grid"></div>

<!-- Tab nav -->
<div class="tabs">
  <div class="tab active" onclick="switchTab('weekly')">Weekly Highlights</div>
  <div class="tab" onclick="switchTab('newsletter')">📰 Newsletter IOCs</div>
  <div class="tab" onclick="switchTab('cves')">CVEs</div>
  <div class="tab" onclick="switchTab('ips')">Malicious IPs</div>
  <div class="tab" onclick="switchTab('iocs')">IOCs</div>
  <div class="tab" onclick="switchTab('actors')">Actors</div>
  <div class="tab" onclick="switchTab('origins')">Origins</div>
</div>

<div id="pane-weekly"     class="pane active"></div>
<div id="pane-newsletter" class="pane"></div>
<div id="pane-cves"       class="pane"></div>
<div id="pane-ips"        class="pane"></div>
<div id="pane-iocs"       class="pane"></div>
<div id="pane-actors"     class="pane"></div>
<div id="pane-origins"    class="pane"></div>

<script>
function sev(s) {
  return `<span class="sev sev-${s}">${s}</span>`;
}
function src(s) {
  const cls = s === 'OTX' ? 'src-otx' : s === 'ThreatFox' ? 'src-tf' : 'src-ab';
  return `<span class="${cls}">${s}</span>`;
}
function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t,i) => {
    const names = ['weekly','newsletter','cves','ips','iocs','actors','origins'];
    t.classList.toggle('active', names[i] === name);
  });
  document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
  document.getElementById('pane-' + name).classList.add('active');
}

async function load() {
  const [stats, weekly, newsletter, cves, ips, iocs, actors, origins] = await Promise.all([
    fetch('threats/stats.json').then(r=>r.json()),
    fetch('threats/weekly.json').then(r=>r.json()),
    fetch('threats/newsletter.json').then(r=>r.json()),
    fetch('threats/cves.json').then(r=>r.json()),
    fetch('threats/ips.json').then(r=>r.json()),
    fetch('threats/iocs.json').then(r=>r.json()),
    fetch('threats/actors.json').then(r=>r.json()),
    fetch('threats/origins.json').then(r=>r.json()),
  ]);

  // Meta
  document.getElementById('meta').textContent =
    `Updated: ${stats.updated}  ·  ${stats.sourcesOnline} sources online`;

  // Stats grid
  const sg = document.getElementById('stats-grid');
  const statItems = [
    ['criticalCves',  'Critical CVEs',     'badge-red'],
    ['maliciousIps',  'Malicious IPs',     'badge-orange'],
    ['iocsThisWeek',  'IOCs This Week',    'badge-blue'],
    ['threatActors',  'Threat Actors',     'badge-purple'],
    ['sourcesOnline', 'Sources Online',    'badge-green'],
  ];
  sg.innerHTML = statItems.map(([k, label, cls]) => `
    <div class="stat">
      <div class="val">${(stats[k] ?? 0).toLocaleString()}</div>
      <div class="lbl">${label}</div>
    </div>`).join('');

  // ── Weekly ─────────────────────────────────────────────────────────────
  const wSum = weekly.summary || {};
  document.getElementById('pane-weekly').innerHTML = `
    <div class="week-header">
      <span class="week-period">${weekly.period || ''}</span>
      <span class="week-tag">${weekly.week || ''}</span>
    </div>

    <div style="padding:16px; display:grid; grid-template-columns:repeat(auto-fill,minmax(140px,1fr)); gap:10px; border-bottom:1px solid #30363d;">
      ${Object.entries({
        'Critical CVEs': wSum.criticalCves,
        'KEV CVEs': wSum.kevCves,
        'Malicious IPs': wSum.maliciousIps,
        'Malware Families': wSum.uniqueMalware,
        'Threat Actors': wSum.uniqueActors,
      }).map(([k,v]) => `<div class="stat"><div class="val">${(v||0).toLocaleString()}</div><div class="lbl">${k}</div></div>`).join('')}
    </div>

    <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; padding:16px;">

      <div class="section">
        <div class="section-header"><h3>🔴 Top CVEs by CVSS</h3></div>
        <table>
          <thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>KEV</th></tr></thead>
          <tbody>${(weekly.topCves||[]).map(c=>`
            <tr>
              <td><strong>${c.id}</strong><br><span style="color:#8b949e;font-size:12px">${(c.title||'').substring(0,50)}</span></td>
              <td><strong style="color:#f0f6fc">${c.cvss}</strong></td>
              <td>${sev(c.severity)}</td>
              <td>${c.kev ? '<span class="kev-pill">KEV</span>' : '—'}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>

      <div class="section">
        <div class="section-header"><h3>🦠 Top Malware Families</h3></div>
        <table>
          <thead><tr><th>Family</th><th>IOCs</th><th>Sources</th></tr></thead>
          <tbody>${(weekly.topMalware||[]).map(m=>`
            <tr>
              <td><strong>${m.name}</strong></td>
              <td>${m.iocs}</td>
              <td>${(m.sources||[]).map(src).join(' ')}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>

      <div class="section">
        <div class="section-header"><h3>🌐 Top Malicious IPs</h3></div>
        <table>
          <thead><tr><th>IP</th><th>Confidence</th><th>Country</th></tr></thead>
          <tbody>${(weekly.topIps||[]).map(ip=>`
            <tr>
              <td><code style="color:#e6edf3">${ip.ip}</code></td>
              <td><strong style="color:${ip.confidence>=90?'#f85149':'#d29922'}">${ip.confidence}%</strong></td>
              <td>${ip.country}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>

      <div class="section">
        <div class="section-header"><h3>🕵️ Top Threat Actors</h3></div>
        <table>
          <thead><tr><th>Actor</th><th>Origin</th><th>Status</th></tr></thead>
          <tbody>${(weekly.topActors||[]).map(a=>`
            <tr>
              <td><strong>${a.name}</strong></td>
              <td>${a.origin}</td>
              <td><span class="status-dot status-${a.status}"></span>${a.status}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>

    </div>

    <div class="section" style="margin:0 16px 16px">
      <div class="section-header"><h3>🔄 Most Seen IOCs (Cross-Source Duplicates)</h3></div>
      <table>
        <thead><tr><th>Value</th><th>Type</th><th>Seen</th><th>Sources</th></tr></thead>
        <tbody>${(weekly.mostSeenIocs||[]).map(i=>`
          <tr>
            <td><code style="color:#e6edf3">${i.value}</code></td>
            <td>${i.type}</td>
            <td><strong>${i.count}×</strong></td>
            <td>${(i.sources||[]).map(src).join(' ')}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`;

  // ── Newsletter ────────────────────────────────────────────────────────
  const nSum = newsletter.summary || {};
  const seenColors = ['#8b949e','#388bfd','#f85149'];  // 1, 2, 3+ sources
  document.getElementById('pane-newsletter').innerHTML = `
    <div class="week-header" style="flex-wrap:wrap;gap:12px;">
      <span class="week-period">📰 Top IOCs — ${newsletter.period || ''}</span>
      <span class="week-tag">${newsletter.week || ''}</span>
      <span class="week-tag" style="color:#3fb97a">${newsletter.count} IOCs scored</span>
      <span class="week-tag" style="color:#388bfd">${nSum.multiSourceCount || 0} confirmed cross-source</span>
    </div>

    ${nSum.namedActors?.length ? `
    <div style="padding:10px 16px;border-bottom:1px solid #30363d;display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
      <span style="color:#8b949e;font-size:12px;margin-right:4px">Named actors:</span>
      ${nSum.namedActors.map(a=>`<span class="badge badge-red">${a}</span>`).join('')}
    </div>` : ''}

    ${nSum.malwareFamilies?.length ? `
    <div style="padding:10px 16px;border-bottom:1px solid #30363d;display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
      <span style="color:#8b949e;font-size:12px;margin-right:4px">Malware families:</span>
      ${nSum.malwareFamilies.slice(0,15).map(m=>`<span class="badge badge-purple">${m}</span>`).join('')}
    </div>` : ''}

    <table>
      <thead>
        <tr>
          <th>Score</th>
          <th>Value</th>
          <th>Type</th>
          <th>Malware / Actor</th>
          <th>Confidence</th>
          <th>Seen In</th>
          <th>Sources</th>
          <th>Country</th>
          <th>First Seen</th>
        </tr>
      </thead>
      <tbody>
        ${(newsletter.items||[]).map(i => {
          const seenColor = seenColors[Math.min(i.seenIn - 1, 2)];
          const actorStr = i.actor !== 'Unknown' ? `<span style="color:#f85149;font-size:11px">${i.actor}</span>` : '';
          const malwareStr = i.malware ? `<span style="color:#a855f7;font-size:12px">${i.malware}</span>` : '';
          const sep = actorStr && malwareStr ? '<br>' : '';
          return `<tr>
            <td><strong style="color:#f0f6fc">${i.score}</strong></td>
            <td style="max-width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
              <code style="color:#e6edf3">${i.value}</code>
            </td>
            <td><span class="badge badge-gray">${i.type}</span></td>
            <td>${malwareStr}${sep}${actorStr}</td>
            <td><strong style="color:${i.confidence>=90?'#f85149':i.confidence>=75?'#d29922':'#8b949e'}">${i.confidence}</strong></td>
            <td><strong style="color:${seenColor}">${i.seenIn}×</strong></td>
            <td>${(i.sources||[]).map(src).join(' ')}</td>
            <td style="font-size:12px">${i.country || '—'}</td>
            <td style="color:#8b949e;font-size:12px">${i.firstSeen}</td>
          </tr>`;
        }).join('')}
      </tbody>
    </table>`;

  // ── CVEs ──────────────────────────────────────────────────────────────
  document.getElementById('pane-cves').innerHTML = `
    <div style="padding:12px 16px;color:#8b949e;font-size:13px;border-bottom:1px solid #30363d">${cves.count.toLocaleString()} CVEs total</div>
    <table>
      <thead><tr><th>ID</th><th>Title</th><th>Vendor / Product</th><th>CVSS</th><th>Severity</th><th>KEV</th><th>Published</th></tr></thead>
      <tbody>${(cves.items||[]).slice(0,50).map(c=>`
        <tr>
          <td><strong>${c.id}</strong></td>
          <td style="max-width:280px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${c.title}</td>
          <td style="color:#8b949e">${[c.vendor,c.product].filter(Boolean).join(' / ') || '—'}</td>
          <td><strong style="color:#f0f6fc">${c.cvss || '—'}</strong></td>
          <td>${sev(c.severity)}</td>
          <td>${c.kev ? '<span class="kev-pill">KEV</span>' : '—'}</td>
          <td style="color:#8b949e">${c.published || '—'}</td>
        </tr>`).join('')}
      </tbody>
    </table>
    ${cves.count > 50 ? `<div style="padding:12px 16px;color:#8b949e;font-size:13px">Showing 50 of ${cves.count.toLocaleString()} — full data in cves.json</div>` : ''}`;

  // ── IPs ───────────────────────────────────────────────────────────────
  document.getElementById('pane-ips').innerHTML = `
    <div style="padding:12px 16px;color:#8b949e;font-size:13px;border-bottom:1px solid #30363d">${ips.count.toLocaleString()} malicious IPs</div>
    <table>
      <thead><tr><th>IP</th><th>Confidence</th><th>Country</th><th>Org</th><th>Categories</th><th>Last Seen</th></tr></thead>
      <tbody>${(ips.items||[]).slice(0,50).map(ip=>`
        <tr>
          <td><code style="color:#e6edf3">${ip.ip}</code></td>
          <td><strong style="color:${ip.confidence>=90?'#f85149':'#d29922'}">${ip.confidence}%</strong></td>
          <td>${ip.country}</td>
          <td style="color:#8b949e">${ip.org || '—'}</td>
          <td>${(ip.categories||[]).join(', ') || '—'}</td>
          <td style="color:#8b949e">${(ip.lastSeen||'').substring(0,10)}</td>
        </tr>`).join('')}
      </tbody>
    </table>
    ${ips.count > 50 ? `<div style="padding:12px 16px;color:#8b949e;font-size:13px">Showing 50 of ${ips.count.toLocaleString()}</div>` : ''}`;

  // ── IOCs ──────────────────────────────────────────────────────────────
  document.getElementById('pane-iocs').innerHTML = `
    <div style="padding:12px 16px;color:#8b949e;font-size:13px;border-bottom:1px solid #30363d">${iocs.count.toLocaleString()} IOCs</div>
    <table>
      <thead><tr><th>Value</th><th>Type</th><th>Malware</th><th>Actor</th><th>Confidence</th><th>Source</th><th>First Seen</th></tr></thead>
      <tbody>${(iocs.items||[]).slice(0,50).map(i=>`
        <tr>
          <td style="max-width:220px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><code style="color:#e6edf3">${i.value}</code></td>
          <td><span class="badge badge-gray">${i.type}</span></td>
          <td>${i.malware || '—'}</td>
          <td style="color:#8b949e">${i.actor !== 'Unknown' ? i.actor : '—'}</td>
          <td><strong style="color:${i.confidence>=75?'#f85149':'#8b949e'}">${i.confidence}</strong></td>
          <td>${src(i.source)}</td>
          <td style="color:#8b949e">${i.firstSeen}</td>
        </tr>`).join('')}
      </tbody>
    </table>
    ${iocs.count > 50 ? `<div style="padding:12px 16px;color:#8b949e;font-size:13px">Showing 50 of ${iocs.count.toLocaleString()}</div>` : ''}`;

  // ── Actors ────────────────────────────────────────────────────────────
  document.getElementById('pane-actors').innerHTML = `
    <div style="padding:12px 16px;color:#8b949e;font-size:13px;border-bottom:1px solid #30363d">${(actors.items||[]).length.toLocaleString()} threat actors</div>
    <table>
      <thead><tr><th>Name</th><th>Alias</th><th>Origin</th><th>Status</th><th>Targets</th><th>Tactics</th></tr></thead>
      <tbody>${(actors.items||[]).slice(0,50).map(a=>`
        <tr>
          <td><strong>${a.name}</strong></td>
          <td style="color:#8b949e;font-size:12px">${(a.alias||'').substring(0,40) || '—'}</td>
          <td>${a.origin}</td>
          <td><span class="status-dot status-${a.status}"></span>${a.status}</td>
          <td style="color:#8b949e;font-size:12px">${(a.targets||[]).slice(0,3).join(', ') || '—'}</td>
          <td style="color:#8b949e;font-size:12px">${(a.tactics||[]).slice(0,2).join(', ')}</td>
        </tr>`).join('')}
      </tbody>
    </table>`;

  // ── Origins ───────────────────────────────────────────────────────────
  const maxOrig = origins.items?.[0]?.events || 1;
  document.getElementById('pane-origins').innerHTML = `
    <div style="padding:12px 16px;color:#8b949e;font-size:13px;border-bottom:1px solid #30363d">
      ${(origins.total||0).toLocaleString()} total events across ${(origins.items||[]).length} countries
    </div>
    ${(origins.items||[]).map(o => `
      <div class="bar-row">
        <div class="bar-label">${o.country}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${o.pct}%;background:${o.color}"></div></div>
        <div class="bar-val">${o.events.toLocaleString()}</div>
      </div>`).join('')}`;
}

load().catch(e => {
  document.getElementById('meta').textContent = 'Error loading data: ' + e.message;
  console.error(e);
});
</script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Server + open browser
# ---------------------------------------------------------------------------

def main():
    for i, arg in enumerate(sys.argv[1:]):
        if arg == "--port" and i + 2 < len(sys.argv):
            global PORT
            PORT = int(sys.argv[i + 2])

    if not OUTPUT_DIR.exists():
        print(f"ERROR: '{OUTPUT_DIR}' not found. Run the pipeline first:")
        print("  python threat_pipeline.py --no-r2 --quick")
        sys.exit(1)

    if not (OUTPUT_DIR / "threats" / "stats.json").exists():
        print("ERROR: output/threats/stats.json not found. Run the pipeline first.")
        sys.exit(1)

    # Write the preview HTML into output/ so relative fetches work
    PREVIEW.write_text(HTML, encoding="utf-8")

    os.chdir(OUTPUT_DIR)

    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass   # suppress request logs

    url = f"http://localhost:{PORT}/preview.html"
    print(f"  Preview server: {url}")
    print("  Press Ctrl+C to stop.\n")

    # Open browser after a short delay so the server is ready
    threading.Timer(0.6, webbrowser.open, args=[url]).start()

    with socketserver.TCPServer(("", PORT), QuietHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()
