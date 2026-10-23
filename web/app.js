/* CTI Dashboard front end. Reads ../data/*.json written by the pipeline. No frameworks. */
(() => {
  const DATA = "data/";                // Nginx serves /srv/cti/data at /data (see deploy/nginx.conf)
  const REFRESH_MS = 5 * 60 * 1000;    // re-read JSON every 5 minutes
  const $ = (s, r = document) => r.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  let records = [], meta = {}, summary = {}, attack = { techniques: {}, groups: {} };
  let query = "", sev = "";

  const ago = (iso) => {
    if (!iso) return "never";
    const m = Math.round((Date.now() - new Date(iso)) / 60000);
    if (m < 1) return "just now";
    if (m < 60) return `${m}m ago`;
    const h = Math.round(m / 60);
    if (h < 48) return `${h}h ago`;
    return `${Math.round(h / 24)}d ago`;
  };

  const matches = (r) => {
    if (sev && r.severity !== sev) return false;
    if (!query) return true;
    const hay = `${r.title} ${r.summary} ${r.tags.join(" ")} ${JSON.stringify(r.extra)}`.toLowerCase();
    return query.split(/\s+/).every((w) => hay.includes(w));
  };

  const tags = (list, limit = 4) => list.slice(0, limit).map((t) => `<span class="tag ${esc(t.toLowerCase().replace(/[^a-z]/g, ""))}">${esc(t)}</span>`).join("");

  const row = (r, metaRight, sub) => `
    <a class="row ${esc(r.severity)}" href="${esc(r.url)}" target="_blank" rel="noopener">
      <span class="bar"></span>
      <span><div class="t">${esc(r.title.length > 72 ? r.title.slice(0, 69) + "..." : r.title)}</div><div class="s">${esc(sub ?? r.summary)}</div>${tags(r.tags)}</span>
      <span class="m">${metaRight}</span>
    </a>`;

  const fill = (id, html, count) => {
    const panel = $(id);
    $(".body", panel).innerHTML = html || `<div class="empty">Nothing matches.</div>`;
    const fid = panel.dataset.feed;
    const fresh = $(".fresh", panel);
    if (fid && fresh) {
      const m = meta[fid] || {};
      const minutes = m.last_success ? (Date.now() - new Date(m.last_success)) / 60000 : Infinity;
      fresh.textContent = m.status === "error" ? `error · last ok ${ago(m.last_success)}` : `${count ?? ""}${count != null ? " · " : ""}updated ${ago(m.last_success)}`;
      fresh.className = "fresh " + (m.status === "error" ? "dead" : minutes > (m.interval_minutes || 60) * 3 ? "stale" : "");
    }
  };

  function renderTiles() {
    const d = summary.last_7d || {};
    const tiles = [
      [d.kev_added, "KEV added · 7d", d.kev_added > 0],
      [d.acsc, "ACSC advisories · 7d", false],
      [d.anz_victims, "AU/NZ ransomware victims · 7d", d.anz_victims > 0],
      [d.ransomware_victims, "Ransomware victims · 7d", false],
      [d.infostealer_iocs, "Infostealer IOCs · 7d", false],
      [d.indicators, "New indicators · 7d", false],
      [`${summary.feeds_ok ?? 0}/${summary.feeds_total ?? 0}`, "Feeds healthy", (summary.feeds_ok ?? 0) < (summary.feeds_total ?? 0)],
    ];
    $("#tiles").innerHTML = tiles.map(([n, l, hot]) => `<div class="tile"><div class="n ${hot ? "hot" : ""}">${esc(n ?? 0)}</div><div class="l">${esc(l)}</div></div>`).join("");
    const ok = summary.feeds_ok ?? 0, total = summary.feeds_total ?? 0;
    $("#healthDot").className = "dot " + (total === 0 ? "" : ok === total ? "ok" : ok >= total / 2 ? "warn" : "err");
    $("#generated").textContent = summary.generated ? `Last pipeline run ${summary.generated} (${ago(summary.generated)})` : "No pipeline run yet";
  }

  function renderPanels() {
    const f = records.filter(matches).filter((r) => r.feed !== "tridentstack" || r.extra.source_type === "api");

    const kev = f.filter((r) => r.feed === "tridentstack").sort((a, b) => (b.extra.priority || 0) - (a.extra.priority || 0));
    fill("#p-kev", kev.slice(0, 40).map((r) => row(r,
      `<b>P ${r.extra.priority ?? "-"}</b>EPSS ${r.extra.epss != null ? (r.extra.epss * 100).toFixed(0) + "%" : "n/a"} · CVSS ${r.extra.cvss ?? "n/a"}<br>due ${esc(r.extra.due_date ?? "-")}`
    )).join(""), kev.length);

    const acsc = f.filter((r) => r.feed === "acsc");
    fill("#p-acsc", acsc.slice(0, 30).map((r) => row(r, `<b>${esc(r.severity)}</b>${ago(r.published)}`)).join(""), acsc.length);

    const ransom = f.filter((r) => r.type === "incident").sort((a, b) => (b.extra.anz - a.extra.anz) || (a.published < b.published ? 1 : -1));
    fill("#p-ransom", ransom.slice(0, 40).map((r) => row(r, `<b>${esc(r.extra.country || "?")}</b>${ago(r.published)}`, r.extra.sector || "")).join(""), ransom.length);

    const stealers = f.filter((r) => r.extra.infostealer);
    const fams = {};
    stealers.forEach((r) => (fams[r.extra.malware] = (fams[r.extra.malware] || 0) + 1));
    const max = Math.max(1, ...Object.values(fams));
    const famHtml = Object.entries(fams).sort((a, b) => b[1] - a[1]).map(([k, v]) =>
      `<div class="kv"><span class="k">${esc(k)}</span><span class="v">${v} IOCs</span><span class="meter"><i style="width:${(v / max) * 100}%"></i></span></div>`).join("");
    fill("#p-stealer", famHtml + stealers.slice(0, 15).map((r) => row(r, `<b>${esc(r.extra.ioc_type)}</b>${ago(r.published)}`, r.extra.malware)).join(""), stealers.length);

    const iocs = f.filter((r) => r.type === "indicator" && !r.extra.infostealer);
    fill("#p-ioc", iocs.slice(0, 40).map((r) => row(r, `<b>${esc(r.extra.ioc_type)}</b>${ago(r.published)}`)).join(""), iocs.length);

    // ATT&CK: technique frequency across tracked groups, plus group alias table
    const techCount = {};
    Object.values(attack.groups).forEach((g) => g.techniques.forEach((t) => (techCount[t] = (techCount[t] || 0) + 1)));
    const tmax = Math.max(1, ...Object.values(techCount));
    const techHtml = Object.entries(techCount).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([t, n]) =>
      `<div class="kv"><span class="k">${esc(t)} ${esc(attack.techniques[t]?.name || "")}</span><span class="v">${n} groups</span><span class="meter"><i style="width:${(n / tmax) * 100}%"></i></span></div>`).join("");
    const groupHtml = Object.entries(attack.groups).filter(([, g]) => !query || `${g.name} ${g.aliases.join(" ")}`.toLowerCase().includes(query)).slice(0, 12).map(([id, g]) =>
      `<a class="row info" href="${esc(g.url)}" target="_blank" rel="noopener"><span class="bar"></span><span><div class="t">${esc(g.name)} <span class="tag">${esc(id)}</span></div><div class="s">aka ${esc(g.aliases.join(", ") || "-")}</div></span><span class="m"><b>${g.techniques.length}</b>techniques</span></a>`).join("");
    fill("#p-attack", techHtml + groupHtml, Object.keys(attack.groups).length);

    const news = f.filter((r) => r.type === "news");
    fill("#p-news", news.slice(0, 60).map((r) => row(r, `<b>${esc(r.extra.source || "")}</b>${ago(r.published)}`)).join(""), news.length);

    const rows = Object.entries(meta).sort().map(([id, m]) =>
      `<tr><td class="mono">${esc(id)}</td><td>${esc(m.name || "")}</td><td class="${esc(m.status || "")}">${esc(m.status || "unknown")}</td><td class="mono">${esc(m.count ?? "-")}</td><td class="mono">${ago(m.last_success)}</td><td class="mono">${esc(m.interval_minutes ?? "-")}m</td><td class="mono">${esc(m.error || "")}</td></tr>`).join("");
    $("#p-health .body").innerHTML = `<table class="health"><thead><tr><th>feed</th><th>source</th><th>status</th><th>records</th><th>last ok</th><th>interval</th><th>error</th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  async function load() {
    try {
      const bust = `?t=${Date.now()}`;
      [records, meta, summary, attack] = await Promise.all([
        fetch(DATA + "records.json" + bust).then((r) => r.json()),
        fetch(DATA + "meta.json" + bust).then((r) => r.json()),
        fetch(DATA + "summary.json" + bust).then((r) => r.json()),
        fetch(DATA + "attack.json" + bust).then((r) => r.json()).catch(() => ({ techniques: {}, groups: {} })),
      ]);
    } catch (e) {
      $("#generated").textContent = "Could not load data files: " + e.message;
    }
    renderTiles();
    renderPanels();
  }

  $("#search").addEventListener("input", (e) => { query = e.target.value.trim().toLowerCase(); renderPanels(); });
  $("#sevFilter").addEventListener("change", (e) => { sev = e.target.value; renderPanels(); });
  const tick = () => ($("#clock").textContent = new Date().toLocaleString("en-AU", { timeZone: "Australia/Melbourne", hour12: false }) + " AEDT/AEST");
  tick(); setInterval(tick, 1000);
  load(); setInterval(load, REFRESH_MS);
})();






