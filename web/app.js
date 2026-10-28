/* ThreatViz front end. Reads ../data/*.json written by the pipeline. No frameworks. */
(() => {
  const DATA = "data/";                // Nginx serves /srv/cti/data at /data (see deploy/nginx.conf)
  const REFRESH_MS = 5 * 60 * 1000;    // re-read JSON every 5 minutes
  const $ = (s, r = document) => r.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const THREADS_KEY = "cti-dashboard-chat-threads-v1";
  const MAX_SAVED_THREADS = 20;
  const MAX_SAVED_MESSAGES = 30;

  let records = [], meta = {}, summary = {}, attack = { techniques: {}, groups: {} };
  let query = "", sev = "";
  let threads = loadThreads();
  let activeThreadId = threads[0]?.id || null;

  const chatStatus = (message) => { $("#chatStatus").textContent = message; };
  function loadThreads() {
    try {
      const saved = JSON.parse(localStorage.getItem(THREADS_KEY) || "[]");
      if (!Array.isArray(saved)) return [];
      return saved.filter((thread) =>
        thread && typeof thread.id === "string" && typeof thread.title === "string" &&
        Array.isArray(thread.messages)
      ).map((thread) => ({
        ...thread,
        messages: thread.messages.filter((message) =>
          message && ["user", "assistant"].includes(message.role) &&
          typeof message.content === "string"
        ).map((message) => ({
          role: message.role,
          content: message.content.slice(0, 4000),
          sources: Array.isArray(message.sources) ? message.sources : [],
        })).slice(-MAX_SAVED_MESSAGES),
      })).slice(0, MAX_SAVED_THREADS);
    } catch (error) {
      console.warn("Could not read saved chat history:", error);
      return [];
    }
  }

  function saveThreads() {
    try {
      threads = threads.filter((thread) => thread.messages.length);
      threads = threads.slice(0, MAX_SAVED_THREADS);
      localStorage.setItem(THREADS_KEY, JSON.stringify(threads));
    } catch (error) {
      console.warn("Could not save chat history in this browser:", error);
      chatStatus("Conversation is available for this session, but browser storage could not save it.");
    }
  }

  function activeThread() {
    return threads.find((thread) => thread.id === activeThreadId) || null;
  }

  function makeThread() {
    return {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      title: "New conversation",
      updated: new Date().toISOString(),
      messages: [],
    };
  }

  function appendInline(parent, text) {
    const pattern = /(`[^`\n]+`|\*\*[^*]+\*\*|__[^_]+__|\*[^*\n]+\*|_[^_\n]+_|\[[^\]]+\]\(https:\/\/[^)\s]+\))/g;
    let offset = 0;
    for (const match of text.matchAll(pattern)) {
      parent.append(document.createTextNode(text.slice(offset, match.index)));
      const token = match[0];
      let node;
      if (token.startsWith("`")) {
        node = document.createElement("code");
        node.textContent = token.slice(1, -1);
      } else if (token.startsWith("**") || token.startsWith("__")) {
        node = document.createElement("strong");
        node.textContent = token.slice(2, -2);
      } else if (token.startsWith("*") || token.startsWith("_")) {
        node = document.createElement("em");
        node.textContent = token.slice(1, -1);
      } else {
        const labelEnd = token.indexOf("](");
        const href = token.slice(labelEnd + 2, -1);
        try {
          const url = new URL(href);
          if (url.protocol !== "https:") throw new Error("Unsupported link protocol");
          node = document.createElement("a");
          node.href = url.href;
          node.target = "_blank";
          node.rel = "noopener";
          node.textContent = token.slice(1, labelEnd);
        } catch {
          node = document.createTextNode(token);
        }
      }
      parent.append(node);
      offset = match.index + token.length;
    }
    parent.append(document.createTextNode(text.slice(offset)));
  }

  function renderMarkdown(container, text) {
    const lines = String(text).split(/\r?\n/);
    let paragraph = [];
    let list = null;
    let codeLines = null;

    const flushParagraph = () => {
      if (!paragraph.length) return;
      const p = document.createElement("p");
      appendInline(p, paragraph.join(" "));
      container.append(p);
      paragraph = [];
    };
    const flushList = () => {
      if (!list) return;
      container.append(list);
      list = null;
    };

    for (const line of lines) {
      if (line.trim().startsWith("```")) {
        flushParagraph();
        flushList();
        if (codeLines) {
          const pre = document.createElement("pre");
          const code = document.createElement("code");
          code.textContent = codeLines.join("\n");
          pre.append(code);
          container.append(pre);
          codeLines = null;
        } else {
          codeLines = [];
        }
        continue;
      }
      if (codeLines) {
        codeLines.push(line);
        continue;
      }
      const heading = line.match(/^(#{1,3})\s+(.+)$/);
      if (heading) {
        flushParagraph();
        flushList();
        const h = document.createElement(`h${heading[1].length + 2}`);
        appendInline(h, heading[2]);
        container.append(h);
        continue;
      }
      const bullet = line.match(/^\s*[-*]\s+(.+)$/);
      const numbered = line.match(/^\s*\d+[.)]\s+(.+)$/);
      if (bullet || numbered) {
        flushParagraph();
        const kind = bullet ? "ul" : "ol";
        if (list && list.tagName.toLowerCase() !== kind) flushList();
        if (!list) list = document.createElement(kind);
        const item = document.createElement("li");
        appendInline(item, (bullet || numbered)[1]);
        list.append(item);
        continue;
      }
      if (!line.trim()) {
        flushParagraph();
        flushList();
      } else {
        flushList();
        paragraph.push(line.trim());
      }
    }
    if (codeLines) {
      const pre = document.createElement("pre");
      const code = document.createElement("code");
      code.textContent = codeLines.join("\n");
      pre.append(code);
      container.append(pre);
    }
    flushParagraph();
    flushList();
  }

  function renderConversation(pendingQuestion = "") {
    const container = $("#chatAnswer");
    container.replaceChildren();
    const thread = activeThread();
    if (!thread || !thread.messages.length) {
      const welcome = document.createElement("div");
      welcome.className = "welcome";
      const mark = document.createElement("span");
      mark.className = "welcome-mark";
      mark.textContent = "✦";
      const title = document.createElement("h2");
      title.textContent = "How can I help with your threat intelligence?";
      const intro = document.createElement("p");
      intro.textContent = "Ask a question about the dashboard, or choose a starting point.";
      const suggestions = document.createElement("div");
      suggestions.className = "suggestions";
      [
        "What are the highest-priority exploited vulnerabilities?",
        "Are any intelligence feeds stale or failing?",
        "Explain CVE-2021-44228",
      ].forEach((prompt) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "suggestion";
        button.dataset.prompt = prompt;
        button.textContent = prompt;
        suggestions.append(button);
      });
      welcome.append(mark, title, intro, suggestions);
      container.append(welcome);
    } else {
      thread.messages.forEach((item) => appendChatTurn(container, item));
    }
    if (pendingQuestion) {
      const pending = document.createElement("article");
      pending.className = "chat-turn user pending";
      const label = document.createElement("strong");
      label.textContent = "You";
      const message = document.createElement("div");
      renderMarkdown(message, pendingQuestion);
      pending.append(label, message);
      container.append(pending);
    }
    container.scrollTop = container.scrollHeight;
    renderThreadList();
  }

  function appendChatTurn(container, item) {
    const turn = document.createElement("article");
    turn.className = `chat-turn ${item.role}`;
    const label = document.createElement("strong");
    label.textContent = item.role === "user" ? "You" : "ThreatViz assistant";
    const message = document.createElement("div");
    message.className = "markdown-body";
    renderMarkdown(message, item.content);
    turn.append(label, message);
    (item.sources || []).forEach((source) => {
      try {
        const url = new URL(source.url);
        if (url.protocol !== "https:") return;
        const link = document.createElement("a");
        link.href = url.href;
        link.target = "_blank";
        link.rel = "noopener";
        const details = [source.feed, source.published].filter(Boolean).join(", ");
        link.textContent = details ? `${source.title} (${details})` : source.title;
        turn.append(link);
      } catch {
        return;
      }
    });
    container.append(turn);
  }

  function renderThreadList() {
    const list = $("#threadList");
    list.replaceChildren();
    threads.filter((thread) => thread.messages.length).forEach((thread) => {
      const row = document.createElement("div");
      row.className = `thread-row${thread.id === activeThreadId ? " active" : ""}`;
      const select = document.createElement("button");
      select.type = "button";
      select.className = "thread-select";
      select.dataset.threadId = thread.id;
      select.textContent = thread.title;
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "thread-delete";
      remove.dataset.deleteThread = thread.id;
      remove.setAttribute("aria-label", `Delete ${thread.title}`);
      remove.textContent = "×";
      row.append(select, remove);
      list.append(row);
    });
  }

  function setWidgetOpen(open) {
    $("#chatWidget").hidden = !open;
    $("#chatBubble").hidden = open;
    $("#chatBubble").setAttribute("aria-expanded", String(open));
    if (open) $("#chatQuestion").focus();
    else $("#chatBubble").focus();
  }

  function newConversation() {
    activeThreadId = null;
    $("#chatQuestion").value = "";
    chatStatus("");
    $("#threadList").hidden = true;
    $("#toggleHistory").setAttribute("aria-expanded", "false");
    renderConversation();
    setWidgetOpen(true);
  }

  $("#newChat").addEventListener("click", newConversation);
  $("#chatBubble").addEventListener("click", () => setWidgetOpen(true));
  $("#chatClose").addEventListener("click", () => setWidgetOpen(false));
  $("#toggleHistory").addEventListener("click", () => {
    const showHistory = $("#threadList").hidden;
    $("#threadList").hidden = !showHistory;
    $("#toggleHistory").setAttribute("aria-expanded", String(showHistory));
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !$("#chatWidget").hidden) setWidgetOpen(false);
  });
  $("#threadList").addEventListener("click", (event) => {
    const deleteButton = event.target.closest("[data-delete-thread]");
    if (deleteButton) {
      threads = threads.filter((thread) => thread.id !== deleteButton.dataset.deleteThread);
      if (activeThreadId === deleteButton.dataset.deleteThread) activeThreadId = threads[0]?.id || null;
      saveThreads();
      renderConversation();
      return;
    }
    const threadButton = event.target.closest("[data-thread-id]");
    if (threadButton) {
      activeThreadId = threadButton.dataset.threadId;
      $("#chatQuestion").value = "";
      chatStatus("");
      renderConversation();
      $("#threadList").hidden = true;
      $("#toggleHistory").setAttribute("aria-expanded", "false");
      setWidgetOpen(true);
    }
  });
  $("#chatAnswer").addEventListener("click", (event) => {
    const suggestion = event.target.closest("[data-prompt]");
    if (suggestion) {
      $("#chatQuestion").value = suggestion.dataset.prompt;
      $("#chatForm").requestSubmit();
    }
  });
  $("#chatQuestion").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      $("#chatForm").requestSubmit();
    }
  });
  $("#chatQuestion").addEventListener("input", (event) => {
    event.target.style.height = "auto";
    event.target.style.height = `${Math.min(event.target.scrollHeight, 130)}px`;
  });

  if (location.protocol !== "https:") {
    chatStatus("Chat requires HTTPS. Configure a domain and TLS to use the assistant.");
  }
  $("#chatForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (location.protocol !== "https:") {
      chatStatus("Chat is available only over HTTPS.");
      return;
    }
    const questionInput = $("#chatQuestion");
    const question = questionInput.value.trim();
    if (!question) return;
    if (!activeThreadId) {
      const thread = makeThread();
      threads.unshift(thread);
      activeThreadId = thread.id;
    }
    const thread = activeThread();
    const history = thread.messages
      .filter((message) => message.role === "user" || message.role === "assistant")
      .slice(-4)
      .map((message) => ({ role: message.role, content: message.content.slice(0, 1000) }));
    const sendButton = $("#chatSend");
    sendButton.disabled = true;
    chatStatus("Asking the assistant…");
    renderConversation(question);
    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question, history }),
      });
      const responseText = await response.text();
      let payload;
      try {
        payload = JSON.parse(responseText);
      } catch {
        throw new Error(
          `Chat service returned a non-JSON response (HTTP ${response.status}). Check the chat service and Nginx logs.`
        );
      }
      if (!response.ok) throw new Error(payload.error || `Request failed (${response.status}).`);
      thread.messages.push(
        { role: "user", content: question },
        { role: "assistant", content: payload.answer, sources: payload.sources || [] }
      );
      thread.title = thread.messages.length === 2 ? question.slice(0, 42) : thread.title;
      thread.updated = new Date().toISOString();
      thread.messages = thread.messages.slice(-MAX_SAVED_MESSAGES);
      threads.sort((a, b) => Date.parse(b.updated) - Date.parse(a.updated));
      saveThreads();
      renderConversation();
      chatStatus(payload.generated ? `Dashboard snapshot: ${payload.generated}` : "");
      questionInput.value = "";
    } catch (error) {
      const message = error.message || "Chat request failed.";
      chatStatus(message);
      renderConversation();
    } finally {
      sendButton.disabled = false;
    }
  });

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
      [d.acsc, "CISA advisories · 7d", false],
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
    const f = records.filter(matches);

    const kev = f.filter((r) => r.feed === "kev").sort((a, b) => (b.extra.priority || 0) - (a.extra.priority || 0));
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
  renderConversation();
  const tick = () => ($("#clock").textContent = new Date().toLocaleString("en-AU", { timeZone: "Australia/Melbourne", hour12: false }) + " AEDT/AEST");
  tick(); setInterval(tick, 1000);
  load(); setInterval(load, REFRESH_MS);
})();
