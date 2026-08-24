
document.addEventListener("DOMContentLoaded", function() {
  const form = document.getElementById("upload-form");
  const scanBtn = document.getElementById("scan-btn");
  const resultsDiv = document.getElementById("scan-results");
  const alertArea = document.getElementById("alert-area");
  const lastScan = document.getElementById("last-scan");
  const fileInput = document.getElementById("file-input");

  // Helper: safe getter (avoid undefined errors)
  function sget(obj, path, fallback = "N/A") {
    try {
      if (!obj) return fallback;
      const parts = path.split(".");
      let cur = obj;
      for (const p of parts) {
        if (cur[p] === undefined || cur[p] === null) return fallback;
        cur = cur[p];
      }
      return cur;
    } catch (e) { return fallback; }
  }

  // Submit
  form.addEventListener("submit", function(evt) {
    evt.preventDefault();
    alertArea.innerHTML = "";
    resultsDiv.innerHTML = `<div class="text-center muted py-4">Scanning attachment — this can take a few seconds...</div>`;
    scanBtn.disabled = true;

    const fd = new FormData(form);
    const scanUrl = form.dataset.scanUrl;
    console.log("Scan URL:", scanUrl);
    fetch(scanUrl, {
      method: "POST",
      body: fd,
      credentials: "same-origin"
    })
    .then(r => r.json())
    .then(payload => {
      scanBtn.disabled = false;
      if (!payload.ok) {
        resultsDiv.innerHTML = `<div class="alert alert-danger mt-5">Scan failed: ${payload.error || "unknown error"}</div>`;
        lastScan.textContent = "Last scan: failed";
        return;
      }

      // Update last scan
      lastScan.textContent = "Last scan: " + new Date().toLocaleString();

      // Show file info
      const file = payload.file || {};
      const fname = file.file_name || "Uploaded file";
      const fsize = file.size || 0;
      const fsha = file.sha256 || "N/A";
      const mime = file.mime || "application/octet-stream";

      const isPhish = !!payload.is_phishing;
      alertArea.innerHTML = isPhish
        ? `<div class="phish-alert badge-danger">⚠ Phishing/blacklist detected in file</div>`
        : `<div class="phish-alert badge-safe">✔ No phishing detected</div>`;

      // Build results: file header
      let html = `<div class="file-meta mb-3">
                    <div>
                      <div style="font-weight:700; font-size:1.05rem;">${sanitizehtml(fname)}</div>
                      <div class="muted" style="font-size:0.88rem;">${mime} • ${formatBytes(fsize)}</div>
                    </div>
                    <div style="margin-left:auto; text-align:right;">
                      <div class="small-muted">SHA256</div>
                      <div style="font-family:monospace; font-size:0.82rem;">${fsha}</div>
                    </div>
                  </div>`;

      // Process URLs
      const urls = Array.isArray(payload.urls) ? payload.urls : [];
      if (urls.length === 0) {
        html += `<div class="text-center muted py-4">No URLs found in the uploaded file.</div>`;
        resultsDiv.innerHTML = html;
        return;
      }

      // Render each URL as a modern card
      urls.forEach((u, idx) => {
        const url = sget(u, "url", u.url || "Unknown");
        const ip = sget(u.ip_address || "ip_address" || "N/A");
        const geo = u.ip_geolocation || {};
        const city = geo.city || "";
        const region = geo.region || "";
        const country = geo.country || "";
        const loc = (geo.city || geo.region || geo.country) ? [geo.city, geo.region, geo.country].filter(Boolean).join(", ") : "N/A";
        const ssl = sget(u, "ssl_issuer", "Unknown");
        const entropy = (u.entropy === undefined || u.entropy === null) ? "N/A" : u.entropy;
        const ml = (u.ml_score === undefined || u.ml_score === null) ? "N/A" : u.ml_score;
        const domain_age = (u.domain_age === undefined || u.domain_age === null) ? "N/A" : u.domain_age;
        const domain_expiry=(u.domain_expiry === undefined || u.domain_expiry === null) ? "N/A" : u.domain_expiry;
        const ttl = (u.ttl === undefined || u.ttl === null) ? "N/A" : u.ttl;
        const dns = (u.dns_record === undefined || u.dns_record === null) ? "N/A" : u.dns_record;
        const blacklist = u.blacklist || { blacklisted: false, source: "N/A", details: "N/A" };
        const isMal = !!u.is_malicious;

        const decisionHtml = isMal
          ? `<span class="badge-danger">⚠ Malicious</span>`
          : `<span class="badge-safe">Safe</span>`;

        // Card HTML
        html += `<div class="url-card" data-idx="${idx}">
                  <div class="url-left">
                    <div style="font-size:0.95rem; font-weight:600; margin-bottom:6px; word-break:break-word;">
                      <a href="${safeurl(url)}" target="_blank" rel="noopener noreferrer">${sanitizehtml(url)}</a>
                    </div>
                    <div class="meta-row">
                      <div class="small-muted">IP: <strong style="color:#0b1720;">${sanitizehtml(u.ip_address)}</strong></div>
                      <div class="small-muted">Location: <strong style="color:#0b1720;">${sanitizehtml(loc)}</strong></div>
                      <div class="small-muted">SSL: <strong style="color:#0b1720;">${sanitizehtml(ssl)}</strong></div>
                    </div>

                    <div class="details-grid">
                      <div class="detail-pill">Entropy: ${sanitizehtml(String(entropy))}</div>
                      <div class="detail-pill">ML score: ${sanitizehtml(String(ml))}</div>
                      <div class="detail-pill">Domain age: ${sanitizehtml(String(u.domain_age))}</div>
                      <div class="detail-pill">TTL: ${sanitizehtml(String(ttl))}</div>
                      <div class="detail-pill">DNS rec: ${sanitizehtml(String(dns))}</div>
                      <div class="detail-pill">Has IP: ${sanitizehtml(String(u.has_ip ?? 'N/A'))}</div>
                    </div>
                  </div>

                  <div class="url-right">
                    <div style="margin-bottom:10px;">${decisionHtml}</div>
                    <button class="btn btn-sm btn-outline-secondary toggle-details toggle-btn">Show details</button>
                  </div>

                  <!-- hidden detailed box -->
                  <div class="full-details" style="display:none; width:100%; margin-top:12px; grid-column:1/-1;">
                    <div style="margin-top:12px; display:flex; gap:12px; flex-wrap:wrap;">
                      <div style="flex:1; min-width:220px;">
                        <div style="font-weight:700; margin-bottom:6px;">DNS & WHOIS</div>
                        <div class="small-muted">DNS record: ${sanitizehtml(String(dns))}</div>
                        <div class="small-muted">Domain age: ${sanitizehtml(String(domain_age))}</div>
                        <div class="small-muted">Domain expiry: ${sanitizehtml(String(u.domain_expiry ?? 'N/A'))}</div>
                        <div class="small-muted">TTL: ${sanitizehtml(String(ttl))}</div>
                      </div>

                      <div style="flex:1; min-width:220px;">
                        <div style="font-weight:700; margin-bottom:6px;">HTML / SSL / Server</div>
                        <div class="small-muted">Forms: ${sanitizehtml(String(u.forms ?? 'N/A'))}</div>
                        <div class="small-muted">Iframes: ${sanitizehtml(String(u.iframes ?? 'N/A'))}</div>
                        <div class="small-muted">JS includes ratio: ${sanitizehtml(String(u.js_includes ?? 'N/A'))}</div>
                        <div class="small-muted">SSL issuer: ${sanitizehtml(ssl)}</div>
                      </div>

                      <div style="flex:1; min-width:240px;">
                        <div style="font-weight:700; margin-bottom:6px;">Blacklist & ML</div>
                        <div style="height:12px;"></div>
                        <div style="font-weight:700; margin-bottom:6px;">VirusTotal</div>
                        <div class="small-muted">
                          Detects: ${ sanitizehtml(String(u.vt_url_report?.detects ?? 'N/A')) }
                        </div>
                        <div class="small-muted">
                          Clean Results: ${ sanitizehtml(String(u.vt_url_report?.clean ?? 'N/A')) }
                        </div>
                        <div class="small-muted">
                          Suspicious: ${ sanitizehtml(String(u.vt_url_report?.suspicious ?? 'N/A')) }
                        </div>
                        <div class="small-muted">
                          Harmless: ${ sanitizehtml(String(u.vt_url_report?.harmless ?? 'N/A')) }
                        </div>
                        <div class="small-muted">
                          VT Score: ${ sanitizehtml(String(u.vt_url_report?.score ?? 'N/A')) }
                        </div>
                        <div class="small-muted">
                          VT Link: 
                          ${ u.vt_url_report?.permalink 
                              ? `<a href="${escapeAttr(u.vt_url_report.permalink)}" target="_blank">View on VT</a>`
                              : "N/A"
                          }
                        </div>

                        <div class="small-muted">Blacklisted: ${blacklist.blacklisted ? 'YES' : 'NO'}</div>
                        <div class="small-muted">Source: ${sanitizehtml(blacklist.source || 'N/A')}</div>
                        <div class="small-muted">Details: ${sanitizehtml(blacklist.details || 'N/A')}</div>
                        <div style="height:8px;"></div>
                        <div class="small-muted">Final decision: ${isMal ? '<strong style="color:#a61b1b;">Malicious</strong>' : '<strong style="color:#007a6d;">Safe</strong>'}</div>
                      </div>
                    </div>

                    <div style="margin-top:12px;">
                      <div style="font-weight:700; margin-bottom:6px;">Raw features (truncated)</div>
                      <pre class="raw-pre">${sanitizehtml(JSON.stringify(u.raw_features || u, null, 2))}</pre>
                    </div>
                  </div>
                </div>`; // end url-card
      }); // end urls.forEach

      resultsDiv.innerHTML = html;

      // wire toggles
      document.querySelectorAll('.toggle-details').forEach(btn => {
        btn.addEventListener('click', function(e) {
          const card = this.closest('.url-card');
          if (!card) return;
          const full = card.querySelector('.full-details');
          if (!full) return;
          if (full.style.display === 'none' || full.style.display === '') {
            full.style.display = 'block';
            this.textContent = 'Hide details';
            // smooth scroll into view on mobile
            full.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          } else {
            full.style.display = 'none';
            this.textContent = 'Show details';
          }
        });
      });

    })
    .catch(err => {
      console.error(err);
      scanBtn.disabled = false;
      resultsDiv.innerHTML = `<div class="alert alert-danger">Scan failed (network or server error).</div>`;
      lastScan.textContent = "Last scan: error";
    });

  }); // end submit handler

  // --- UTILITIES ---
  // function sanitizehtml(s) {
  //   if (s === null || s === undefined) return "";
  //   return String(s)
  //     .replace(/&/g, "&amp;")
  //     .replace(/</g, "&lt;")
  //     .replace(/>/g, "&gt;")
  //     .replace(/"/g, "&quot;");
  // }

  function sanitizehtml(str) {
    const div = document.createElement("div");
    div.textContent = str ?? "";
    return div.innerHTML;
}

  function escapeAttr(s) {
    if (s === null || s === undefined) return "";
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function safeurl(url){
    try{
      const u = new URL(url);
      return ["http:","https:"].includes(u.protocol) ?u.href:"#";
    }catch(e){
      return "#";
    }

  }


  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return "0 B";
    const sizes = ['B','KB','MB','GB','TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return parseFloat((bytes / Math.pow(1024, i)).toFixed(2)) + ' ' + sizes[i];
  }
});