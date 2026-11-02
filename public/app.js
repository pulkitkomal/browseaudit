const view = document.getElementById("view");
const urlInput = document.getElementById("url");
const findingsEl = document.getElementById("findings");
const countsEl = document.getElementById("counts");
const filtersEl = document.getElementById("filters");
const qualityFiltersEl = document.getElementById("quality-filters");
const qualityListEl = document.getElementById("quality-list");
const qualityScoreEl = document.getElementById("quality-score");
const qualityText = document.getElementById("quality-text");
const openImprovements = document.getElementById("open-improvements");
const improvementsDlg = document.getElementById("improvements");
const networkEl = document.getElementById("network");
const requestCount = document.getElementById("request-count");
const llmBanner = document.getElementById("llm-banner");
const pageTitle = document.getElementById("page-title");
const httpStatus = document.getElementById("http-status");
const lock = document.getElementById("lock");
const emptyEl = document.getElementById("empty");
const settingsDlg = document.getElementById("settings");
const fixesDlg = document.getElementById("fixes");
const summaryRisk = document.getElementById("summary-risk");
const summaryLayman = document.getElementById("summary-layman");
const summaryText = document.getElementById("summary-text");
const openFixes = document.getElementById("open-fixes");
const exportReport = document.getElementById("export-report");
const gradeEl = document.getElementById("grade");
const gradeScore = document.getElementById("grade-score");
const scopeHostsEl = document.getElementById("scope-hosts");
const scopePrompt = document.getElementById("scope-prompt");
const scopePromptText = document.getElementById("scope-prompt-text");
const inventoryEl = document.getElementById("inventory");

const state = {
  findings: [],
  requests: [],
  pages: [],
  scope: [],
  filter: "all",
  qualityFilter: "all",
  panel: "findings",
  view: "page",
  currentUrl: "",
  pendingScope: null,
  settings: { configured: false, model: "gpt-4o-mini", baseUrl: "https://api.openai.com/v1" },
  llmSummaries: [],
  plan: null,
  qualityPlan: null,
};

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const PENALTY = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };

function labUrl() {
  return `${location.protocol}//${location.host}/lab/`;
}

function toProxyPath(target) {
  const u = new URL(target);
  return `/proxy/${u.protocol.replace(":", "")}/${u.host}${u.pathname}${u.search}`;
}

function fromFrameLocation() {
  try {
    const href = view.contentWindow.location.href;
    const u = new URL(href);
    if (!u.pathname.startsWith("/proxy/")) return href;
    const rest = u.pathname.slice("/proxy/".length) + u.search;
    const schemeEnd = rest.indexOf("/");
    if (schemeEnd <= 0) return href;
    return `${rest.slice(0, schemeEnd)}://${rest.slice(schemeEnd + 1)}`;
  } catch {
    return urlInput.value;
  }
}

function normalizeInput(raw) {
  const value = String(raw || "").trim();
  if (!value) return "";
  if (value.startsWith("/")) return `${location.protocol}//${location.host}${value}`;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value)) return `https://${value}`;
  return value;
}

function hostOf(target) {
  try {
    return new URL(target).host.toLowerCase();
  } catch {
    return "";
  }
}

function samePage(a, b) {
  if (!a || !b) return false;
  try {
    const strip = (value) => {
      const u = new URL(value);
      u.hash = "";
      let path = u.pathname || "/";
      if (path.endsWith("/index.html")) path = path.slice(0, -10) || "/";
      if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
      return `${u.protocol}//${u.host}${path}${u.search}`;
    };
    return strip(a) === strip(b);
  } catch {
    return a === b;
  }
}

function isLabUrl(target) {
  try {
    const u = new URL(target);
    return u.pathname.startsWith("/lab") && u.host === location.host;
  } catch {
    return false;
  }
}

function inScope(host) {
  const normalized = String(host || "").toLowerCase();
  return state.scope.includes(normalized) || state.scope.includes(normalized.split(":")[0]);
}

function showIdle() {
  emptyEl.hidden = false;
  urlInput.value = "";
  pageTitle.textContent = "";
  httpStatus.textContent = "";
  lock.textContent = "";
  lock.classList.remove("secure");
  state.currentUrl = "";
  view.removeAttribute("src");
  hideScopePrompt();
}

function loadFrame(target) {
  emptyEl.hidden = true;
  urlInput.value = target;
  pageTitle.textContent = target;
  state.currentUrl = target;
  lock.textContent = target.startsWith("https:") ? "HTTPS" : "HTTP";
  lock.classList.toggle("secure", target.startsWith("https:"));
  view.src = toProxyPath(target);
  renderAll();
}

async function addScopeHost(host) {
  const result = await fetch("/api/scope", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ add: host }),
  }).then((res) => res.json());
  state.scope = result.hosts || [];
  renderScope();
}

function hideScopePrompt() {
  state.pendingScope = null;
  scopePrompt.hidden = true;
}

function showScopePrompt(host, url) {
  state.pendingScope = { host, url };
  scopePromptText.textContent = `${host} is outside the current scope (${state.scope.join(", ") || "empty"}). Add it to review that site?`;
  scopePrompt.hidden = false;
}

async function browse(raw) {
  const target = normalizeInput(raw);
  if (!target) {
    showIdle();
    return;
  }
  hideScopePrompt();
  const host = hostOf(target);
  if (isLabUrl(target)) {
    await addScopeHost(host);
    loadFrame(target);
    return;
  }
  const scope = await fetch("/api/scope").then((res) => res.json());
  state.scope = scope.hosts || [];
  if (!state.scope.length || inScope(host)) {
    await addScopeHost(host);
    loadFrame(target);
    return;
  }
  showScopePrompt(host, target);
}

function laneOf(item) {
  return item && item.lane === "quality" ? "quality" : "security";
}

function visibleLane(lane) {
  const list = state.findings.filter((item) => laneOf(item) === lane);
  if (state.view !== "page") return list;
  if (!state.currentUrl) return [];
  return list.filter((item) => samePage(item.url, state.currentUrl));
}

function visibleFindings() {
  return visibleLane("security");
}

function visibleQualityFindings() {
  return visibleLane("quality");
}

function visiblePages() {
  if (state.view !== "page") return state.pages;
  if (!state.currentUrl) return [];
  return state.pages.filter((item) => samePage(item.url, state.currentUrl));
}

function visibleSummaries(kind = "security") {
  const list = state.llmSummaries.filter((item) => (item.kind || "security") === kind);
  if (state.view !== "page") return list;
  if (!state.currentUrl) return [];
  return list.filter((item) => samePage(item.url, state.currentUrl));
}

function groupKey(finding) {
  const id = String(finding.id || finding.title || "");
  const prefix = id.split(":")[0];
  if (
    prefix.startsWith("cookie-") ||
    prefix === "sri-missing" ||
    prefix === "mixed-content" ||
    prefix === "csrf-token-missing" ||
    prefix === "tabnabbing" ||
    prefix === "javascript-url" ||
    prefix === "broken-resource" ||
    prefix === "js-error" ||
    prefix === "unlabeled" ||
    prefix === "empty-button" ||
    prefix === "img-alt-missing" ||
    prefix === "hash-link" ||
    prefix === "viewport-missing" ||
    prefix === "html-lang-missing" ||
    prefix === "title-missing" ||
    prefix === "page-status" ||
    prefix === "tab-reload"
  ) {
    return prefix;
  }
  return id || finding.title;
}

function groupedTitle(key, items) {
  const names = items
    .map((item) => String(item.id || "").split(":").slice(1).join(":"))
    .filter(Boolean);
  if (key === "cookie-secure") return `Set the Secure flag on cookies${names.length ? ` (${names.join(", ")})` : ""}`;
  if (key === "cookie-httponly") return `Set HttpOnly on cookies${names.length ? ` (${names.join(", ")})` : ""}`;
  if (key === "cookie-samesite") return `Tighten SameSite on cookies${names.length ? ` (${names.join(", ")})` : ""}`;
  if (key === "sri-missing") return "Add Subresource Integrity to third-party scripts";
  if (key === "mixed-content") return "Serve every subresource over HTTPS";
  if (key === "csrf-token-missing") return "Add CSRF tokens to POST forms";
  if (key === "tabnabbing") return "Add rel=noopener to target=_blank links";
  if (key === "javascript-url") return "Replace javascript: URLs with proper handlers";
  if (key === "broken-resource") return "Fix scripts, styles, fonts, or images that failed to load";
  if (key === "js-error") return "Stop uncaught JavaScript errors";
  if (key === "unlabeled") return "Label form fields and controls";
  if (key === "empty-button") return "Give buttons an accessible name";
  if (key === "img-alt-missing") return "Add alt text to images";
  if (key === "hash-link") return "Replace placeholder links with real destinations";
  if (key === "viewport-missing") return "Add a viewport meta tag";
  if (key === "html-lang-missing") return "Set lang on the html element";
  if (key === "title-missing") return "Add a page title";
  if (key === "page-status") return "Fix pages that return an error status";
  if (key === "tab-reload") return "Keep tab and in-app switches on the same page instead of reloading";
  return items[0].title;
}

function letterForScore(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function gradeFromFindings(findings, reviewed) {
  const list = findings.slice();
  if (!reviewed && !list.length) {
    return { letter: null, score: null, label: "—" };
  }
  const groups = new Map();
  for (const finding of list) {
    const key = groupKey(finding);
    const prev = groups.get(key);
    if (!prev || (PENALTY[finding.severity] || 0) > (PENALTY[prev.severity] || 0)) groups.set(key, finding);
  }
  let score = 100;
  let worst = null;
  for (const finding of groups.values()) {
    score -= PENALTY[finding.severity] || 0;
    if (!worst || (PENALTY[finding.severity] || 0) > (PENALTY[worst] || 0)) worst = finding.severity;
  }
  score = Math.max(0, Math.min(100, score));
  if (worst === "critical") score = Math.min(score, 59);
  return { letter: list.length ? letterForScore(score) : "A", score, label: list.length ? letterForScore(score) : "A" };
}

function buildPlan(findings, llmSummaries = [], viewMode = "session", reviewed = false) {
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const list = findings.slice();
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of list) {
    if (counts[item.severity] != null) counts[item.severity] += 1;
  }
  const pages = [...new Set(list.map((item) => item.url).filter(Boolean))];
  const worst = SEVERITIES.find((name) => counts[name] > 0) || null;
  const groups = new Map();
  for (const finding of list) {
    const key = groupKey(finding);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(finding);
  }
  const fixes = [...groups.entries()]
    .map(([key, items]) => {
      items.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
      const top = items[0];
      return {
        severity: top.severity,
        title: groupedTitle(key, items),
        why: top.description,
        do: top.recommendation || "Apply a defensive control for this finding.",
        count: items.length,
      };
    })
    .sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));

  let risk = "No findings";
  if (worst === "critical") risk = "Urgent";
  else if (worst === "high") risk = "Needs work";
  else if (worst === "medium") risk = "Harden the site";
  else if (worst) risk = "Minor";

  const bits = SEVERITIES.filter((name) => counts[name]).map((name) => `${counts[name]} ${name}`);
  const parts = [];
  if (!list.length) {
    parts.push(viewMode === "page" ? "No issues on this page yet." : "Open a site. An overall summary will appear here.");
  } else {
    const where = viewMode === "page" ? "This page" : "This session";
    parts.push(
      `${where} has ${bits.join(", ")} finding${list.length === 1 ? "" : "s"}` +
        (viewMode === "session" && pages.length ? ` across ${pages.length} page${pages.length === 1 ? "" : "s"}` : "") +
        "."
    );
    if (fixes[0]) parts.push(`Start with: ${fixes[0].title}.`);
  }
  for (const extra of llmSummaries) {
    if (extra && extra.text) parts.push(extra.text);
  }
  return {
    risk,
    worst,
    summary: parts.join(" "),
    fixes,
    grade: gradeFromFindings(list, reviewed),
  };
}

function qualityScoreFromFindings(findings, reviewed) {
  const list = findings.slice();
  if (!reviewed && !list.length) {
    return { label: "—", tone: "", summary: "Open a page to check whether it works." };
  }
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of list) {
    if (counts[item.severity] != null) counts[item.severity] += 1;
  }
  const worst = SEVERITIES.find((name) => counts[name] > 0) || null;
  if (worst === "critical" || worst === "high" || worst === "medium") {
    return { label: "Needs work", tone: worst === "medium" ? "medium" : "high", counts, worst };
  }
  return { label: "Pass", tone: "ok", counts, worst };
}

function buildQualityPlan(findings, llmSummaries = [], viewMode = "session", reviewed = false) {
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const list = findings.slice();
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of list) {
    if (counts[item.severity] != null) counts[item.severity] += 1;
  }
  const pages = [...new Set(list.map((item) => item.url).filter(Boolean))];
  const score = qualityScoreFromFindings(list, reviewed);
  const groups = new Map();
  for (const finding of list) {
    const key = groupKey(finding);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(finding);
  }
  const fixes = [...groups.entries()]
    .map(([key, items]) => {
      items.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
      const top = items[0];
      return {
        severity: top.severity,
        title: groupedTitle(key, items),
        why: top.description,
        do: top.recommendation || "Fix this so the page works for people using it.",
        count: items.length,
      };
    })
    .sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
  const bits = SEVERITIES.filter((name) => counts[name]).map((name) => `${counts[name]} ${name}`);
  const parts = [];
  if (!list.length) {
    parts.push(viewMode === "page" ? "No quality issues on this page yet." : "Open a page to check whether it works.");
  } else {
    const where = viewMode === "page" ? "This page" : "This session";
    parts.push(
      `${where} has ${bits.join(", ")} quality issue${list.length === 1 ? "" : "s"}` +
        (viewMode === "session" && pages.length ? ` across ${pages.length} page${pages.length === 1 ? "" : "s"}` : "") +
        "."
    );
    if (fixes[0]) parts.push(`Start with: ${fixes[0].title}.`);
  }
  for (const extra of llmSummaries) {
    if (extra && extra.text) parts.push(extra.text);
  }
  return {
    risk: score.label,
    worst: score.worst,
    summary: parts.join(" "),
    fixes,
    score,
  };
}

function mergeFixes(securityFixes, qualityFixes) {
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [
    ...(securityFixes || []).map((item) => ({ ...item, lane: item.lane || "security" })),
    ...(qualityFixes || []).map((item) => ({ ...item, lane: "quality" })),
  ].sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
}

function buildLayman(security, quality) {
  const bits = [];
  const letter = security && security.grade && security.grade.letter;
  if (letter === "F") bits.push("This site would not pass a basic security check.");
  else if (letter) bits.push(`The security grade is ${letter}.`);
  if (security && security.fixes && security.fixes[0]) {
    bits.push(`The first security job is: ${security.fixes[0].title}.`);
  }
  const qualityLabel = quality && quality.score && quality.score.label;
  if (qualityLabel === "Needs work") {
    bits.push("People using it may hit broken pieces, confusing controls, or pages that reload when a tab is clicked.");
  } else if (qualityLabel === "Pass") {
    bits.push("The pages that were opened mostly work.");
  }
  if (quality && quality.fixes && quality.fixes[0]) {
    bits.push(`The first usability job is: ${quality.fixes[0].title}.`);
  }
  if (!bits.length) return "";
  return bits.join(" ");
}

function buildAgentPrompt(security, quality, viewMode) {
  const pages = [
    ...new Set([
      ...visiblePages().map((item) => item.url),
      ...(security.fixes || []).flatMap((item) => item.pages || []),
      ...(quality.fixes || []).flatMap((item) => item.pages || []),
    ]),
  ].filter(Boolean);
  const fixes = mergeFixes(security.fixes, quality.fixes).slice(0, 16);
  const lines = [
    "Implement the BrowseAudit review below.",
    "",
    "Constraints:",
    "- Defensive and quality fixes only. Do not add exploits, payloads, PoCs, or attack steps.",
    "- Do not print or commit secrets. If a secret appeared in HTML or comments, remove it and rotate it; do not repeat the value.",
    "- Do not fill forms, submit credentials, or crawl extra pages.",
    "- Keep the existing product behavior unless a finding requires a change.",
    "",
    `Scope: ${viewMode === "page" ? "this page" : "this browsing session"}.`,
    `Security grade: ${(security.grade && security.grade.letter) || "—"}.`,
    `Quality: ${(quality.score && quality.score.label) || "—"}.`,
  ];
  if (pages.length) {
    lines.push("Pages:");
    for (const url of pages.slice(0, 12)) lines.push(`- ${url}`);
  }
  lines.push("", "Work through these changes in order:", "");
  if (!fixes.length) {
    lines.push("- No concrete fixes were recorded.");
  } else {
    fixes.forEach((item, index) => {
      lines.push(`${index + 1}. [${item.lane || "security"} / ${item.severity}] ${item.title}`);
      if (item.do) lines.push(`   ${item.do}`);
      lines.push("");
    });
  }
  lines.push("When you are done, summarize what changed and what still needs a human.");
  return lines.join("\n");
}

function buildOverallPlan(viewMode, reviewed) {
  const security = buildPlan(visibleFindings(), visibleSummaries("security"), viewMode, reviewed);
  const quality = buildQualityPlan(visibleQualityFindings(), visibleSummaries("quality"), viewMode, reviewed);
  const fixes = mergeFixes(security.fixes, quality.fixes);
  return {
    ...security,
    quality: quality.score,
    qualitySummary: quality.summary,
    fixes,
    summary: [security.summary, quality.fixes.length ? quality.summary : ""].filter(Boolean).join(" "),
    layman: buildLayman(security, quality),
    agentPrompt: buildAgentPrompt(security, quality, viewMode),
  };
}

function renderGrade(grade) {
  const letter = grade && grade.letter ? grade.letter : "—";
  gradeEl.textContent = letter;
  gradeEl.dataset.letter = grade && grade.letter ? grade.letter : "";
  gradeScore.textContent = grade && grade.score != null ? `${grade.score}/100` : "";
}

function renderSummary() {
  const reviewed = visiblePages().length > 0;
  const plan = buildOverallPlan(state.view, reviewed);
  state.plan = plan;
  const qualityLabel = plan.quality && plan.quality.label && plan.quality.label !== "—" ? plan.quality.label : "";
  summaryRisk.textContent = qualityLabel ? `${plan.risk} · Quality ${qualityLabel}` : plan.risk;
  summaryRisk.className = plan.worst || "";
  if (plan.layman) {
    summaryLayman.hidden = false;
    summaryLayman.textContent = plan.layman;
  } else {
    summaryLayman.hidden = true;
    summaryLayman.textContent = "";
  }
  summaryText.textContent = plan.summary;
  openFixes.disabled = plan.fixes.length === 0;
  exportReport.disabled = !reviewed && !state.findings.length;
  renderGrade(plan.grade);
}

function renderFixes(plan, status) {
  const gradeLabel = plan.grade && plan.grade.letter ? `Grade ${plan.grade.letter}` : "No grade";
  const qualityLabel = plan.quality && plan.quality.label ? plan.quality.label : "";
  document.getElementById("fixes-risk").textContent = qualityLabel
    ? `${gradeLabel} · ${plan.risk} · Quality ${qualityLabel}`
    : `${gradeLabel} · ${plan.risk}`;
  document.getElementById("fixes-layman").textContent = plan.layman || "";
  document.getElementById("fixes-summary").textContent = plan.summary;
  document.getElementById("fixes-agent").textContent = plan.agentPrompt || "";
  document.getElementById("fixes-status").textContent = status || "";
  document.getElementById("fixes-list").innerHTML = plan.fixes
    .map(
      (item) => `
      <li>
        <strong><span class="lane">${escapeHtml(item.lane || "security")}</span> ${escapeHtml(item.severity)} · ${escapeHtml(item.title)}</strong>
        <div class="do">${escapeHtml(item.do)}</div>
      </li>`
    )
    .join("");
  fixesDlg.scrollTop = 0;
}

function renderCounts() {}

function filterButtons(source, active) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let openai = 0;
  let heuristic = 0;
  for (const item of source) {
    if (counts[item.severity] != null) counts[item.severity] += 1;
    if (item.source === "openai") openai += 1;
    else heuristic += 1;
  }
  const labels = [
    ["all", source.length],
    ...SEVERITIES.map((name) => [name, counts[name]]),
    ["openai", openai],
    ["heuristic", heuristic],
  ];
  return labels
    .map(
      ([name, n]) =>
        `<button type="button" data-filter="${name}" class="${name} ${active === name ? "active" : ""}">${name} <em>${n}</em></button>`
    )
    .join("");
}

function renderFilters() {
  filtersEl.innerHTML = filterButtons(visibleFindings(), state.filter);
}

function renderQualityFilters() {
  qualityFiltersEl.innerHTML = filterButtons(visibleQualityFindings(), state.qualityFilter);
}

function setPanel(name) {
  state.panel = name === "inventory" || name === "quality" ? name : "findings";
  document.getElementById("panel-findings").hidden = state.panel !== "findings";
  document.getElementById("panel-quality").hidden = state.panel !== "quality";
  document.getElementById("panel-inventory").hidden = state.panel !== "inventory";
  document.getElementById("tab-findings").classList.toggle("active", state.panel === "findings");
  document.getElementById("tab-quality").classList.toggle("active", state.panel === "quality");
  document.getElementById("tab-inventory").classList.toggle("active", state.panel === "inventory");
  document.getElementById("tab-findings").setAttribute("aria-selected", String(state.panel === "findings"));
  document.getElementById("tab-quality").setAttribute("aria-selected", String(state.panel === "quality"));
  document.getElementById("tab-inventory").setAttribute("aria-selected", String(state.panel === "inventory"));
}

function renderViewToggle() {
  document.getElementById("view-page").classList.toggle("active", state.view === "page");
  document.getElementById("view-session").classList.toggle("active", state.view === "session");
}

function findingCards(items) {
  return items
    .map(
      (item) => `
      <article class="card ${item.severity}">
        <div class="meta">
          <span>${item.severity}</span>
          <span>${item.source}</span>
          ${item.lane === "quality" ? "<span>quality</span>" : ""}
          ${item.cwe ? `<span>${item.cwe}</span>` : ""}
          ${item.confidence ? `<span>${item.confidence}</span>` : ""}
        </div>
        <h3>${escapeHtml(item.title)}</h3>
        <p>${escapeHtml(item.description)}</p>
        ${item.evidence ? `<div class="evidence">${escapeHtml(item.evidence)}</div>` : ""}
        ${item.recommendation ? `<p class="fix">${escapeHtml(item.recommendation)}</p>` : ""}
        ${item.url ? `<p class="meta">${escapeHtml(item.url)}</p>` : ""}
      </article>`
    )
    .join("");
}

function filteredItems(source, filter) {
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return source
    .filter((item) => {
      if (filter === "all") return true;
      if (filter === "openai") return item.source === "openai";
      if (filter === "heuristic") return item.source !== "openai";
      return item.severity === filter;
    })
    .sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9) || (b.at || 0) - (a.at || 0));
}

function renderFindings() {
  const source = visibleFindings();
  const items = filteredItems(source, state.filter);
  if (!items.length) {
    findingsEl.innerHTML = `<div class="empty">${
      source.length
        ? "Nothing in this filter."
        : state.view === "page"
          ? "Findings for this page appear here as it loads."
          : "Open a site. Findings appear here as pages load."
    }</div>`;
    return;
  }
  findingsEl.innerHTML = findingCards(items);
}

function renderQuality() {
  const reviewed = visiblePages().length > 0;
  const plan = buildQualityPlan(visibleQualityFindings(), visibleSummaries("quality"), state.view, reviewed);
  state.qualityPlan = plan;
  qualityScoreEl.textContent = plan.score.label;
  qualityScoreEl.dataset.tone = plan.score.tone || "";
  qualityText.textContent = plan.summary;
  openImprovements.disabled = plan.fixes.length === 0;
  renderQualityFilters();
  const source = visibleQualityFindings();
  const items = filteredItems(source, state.qualityFilter);
  if (!items.length) {
    qualityListEl.innerHTML = `<div class="empty">${
      source.length
        ? "Nothing in this filter."
        : state.view === "page"
          ? "Quality issues for this page appear here as it loads."
          : "Open a site. Broken extras, tab reloads, errors, and unusable controls appear here."
    }</div>`;
    return;
  }
  qualityListEl.innerHTML = findingCards(items);
}

function renderImprovements(plan, status) {
  document.getElementById("improvements-risk").textContent = plan.score && plan.score.label ? plan.score.label : "Quality";
  document.getElementById("improvements-summary").textContent = plan.summary;
  document.getElementById("improvements-status").textContent = status || "";
  document.getElementById("improvements-list").innerHTML = plan.fixes
    .map(
      (item) => `
      <li>
        <strong>${escapeHtml(item.severity)} · ${escapeHtml(item.title)}</strong>
        <div class="do">${escapeHtml(item.do)}</div>
      </li>`
    )
    .join("");
  improvementsDlg.scrollTop = 0;
}

function renderNetwork() {
  requestCount.textContent = String(state.requests.length);
  networkEl.innerHTML = state.requests
    .slice(0, 80)
    .map(
      (item) =>
        `<div><span>${escapeHtml(item.method)}</span><span>${item.status || "—"}</span><span>${escapeHtml(item.url)}</span><span>${item.ms}ms</span></div>`
    )
    .join("");
}

function renderScope() {
  if (!state.scope.length) {
    scopeHostsEl.innerHTML = `<span class="scope-empty">None yet. The first URL you open becomes scope.</span>`;
    return;
  }
  scopeHostsEl.innerHTML = state.scope
    .map((host) => `<span class="scope-chip">${escapeHtml(host)}</span>`)
    .join("");
}

function mark(ok) {
  return ok ? "yes" : "no";
}

function uniqueCookies(pages) {
  const seen = new Map();
  for (const page of pages) {
    for (const cookie of page.cookies || []) {
      seen.set(`${cookie.host}|${cookie.name}|${cookie.path}`, cookie);
    }
  }
  return [...seen.values()];
}

function renderInventory() {
  const pages = visiblePages();
  if (!pages.length) {
    inventoryEl.innerHTML = `<p class="inventory-empty">Open a page to see the headers and cookie flags that were actually set.</p>`;
    return;
  }
  const cookies = uniqueCookies(pages);
  const showPage = pages.length > 1;
  const headerRows = pages
    .map((page) => {
      const cells = (page.headers || [])
        .map(
          (row) =>
            `<tr>${showPage ? `<td>${escapeHtml(page.url)}</td>` : ""}<td>${escapeHtml(row.name)}</td><td class="${row.present ? "ok" : "missing"}">${row.present ? "yes" : "missing"}</td><td>${escapeHtml(row.value || "")}</td></tr>`
        )
        .join("");
      return cells;
    })
    .join("");
  const cookieRows = cookies
    .map(
      (cookie) =>
        `<tr><td>${escapeHtml(cookie.name)}</td><td>${escapeHtml(cookie.host)}</td><td class="${cookie.secure ? "ok" : "missing"}">${mark(cookie.secure)}</td><td class="${cookie.httpOnly ? "ok" : "missing"}">${mark(cookie.httpOnly)}</td><td>${escapeHtml(cookie.sameSite || "(unset)")}</td></tr>`
    )
    .join("");
  inventoryEl.innerHTML = `
    <h3>Headers</h3>
    <div class="table-wrap">
      <table>
        <thead><tr>${showPage ? "<th>Page</th>" : ""}<th>Header</th><th>Set</th><th>Value</th></tr></thead>
        <tbody>${headerRows}</tbody>
      </table>
    </div>
    <h3>Cookies</h3>
    <p class="inventory-note">Names and flags only. Values are not stored.</p>
    ${
      cookies.length
        ? `<div class="table-wrap"><table>
            <thead><tr><th>Name</th><th>Host</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr></thead>
            <tbody>${cookieRows}</tbody>
          </table></div>`
        : `<p class="inventory-empty">No cookies on these pages.</p>`
    }`;
}

function renderAll() {
  renderViewToggle();
  renderSummary();
  renderCounts();
  renderFilters();
  renderFindings();
  renderQuality();
  renderNetwork();
  renderScope();
  renderInventory();
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function applyEvent(event) {
  if (event.type === "hello") {
    state.findings = event.findings || [];
    state.requests = event.requests || [];
    state.pages = event.pages || [];
    state.scope = event.scope || [];
    state.llmSummaries = event.llmSummaries || [];
    if (event.settings) state.settings = event.settings;
    renderAll();
    updateLlmBanner();
  } else if (event.type === "reset") {
    state.findings = [];
    state.requests = [];
    state.pages = [];
    state.scope = [];
    state.llmSummaries = [];
    state.currentUrl = "";
    hideScopePrompt();
    renderAll();
  } else if (event.type === "finding") {
    state.findings.unshift(event.finding);
    renderAll();
  } else if (event.type === "request") {
    state.requests.unshift(event.request);
    renderNetwork();
  } else if (event.type === "page") {
    state.pages = state.pages.filter((item) => item.url !== event.page.url);
    state.pages.unshift(event.page);
    state.currentUrl = event.page.url;
    renderAll();
  } else if (event.type === "scope") {
    state.scope = event.hosts || [];
    renderScope();
  } else if (event.type === "out-of-scope") {
    if (event.host) showScopePrompt(event.host, event.url);
  } else if (event.type === "navigation") {
    httpStatus.textContent = event.status ? String(event.status) : "";
    pageTitle.textContent = event.url || pageTitle.textContent;
    if (event.url) state.currentUrl = event.url;
    renderAll();
  } else if (event.type === "llm-start") {
    llmBanner.hidden = false;
    llmBanner.className = "llm-banner";
    llmBanner.textContent = `OpenAI is reviewing ${event.url}…`;
  } else if (event.type === "llm-done") {
    llmBanner.hidden = false;
    llmBanner.className = "llm-banner ok";
    llmBanner.textContent = event.summary || event.qualitySummary
      ? `${event.model}: ${[event.summary, event.qualitySummary].filter(Boolean).join(" ")}`
      : `${event.model} added ${event.count} finding(s).`;
    if (event.summary) {
      state.llmSummaries = state.llmSummaries.filter(
        (item) => !(item.url === event.url && (item.kind || "security") === "security")
      );
      state.llmSummaries.unshift({ url: event.url, text: event.summary, model: event.model, kind: "security" });
    }
    if (event.qualitySummary) {
      state.llmSummaries = state.llmSummaries.filter(
        (item) => !(item.url === event.url && item.kind === "quality")
      );
      state.llmSummaries.unshift({ url: event.url, text: event.qualitySummary, model: event.model, kind: "quality" });
    }
    if (event.summary || event.qualitySummary) {
      renderSummary();
      renderQuality();
    }
  } else if (event.type === "llm-error") {
    llmBanner.hidden = false;
    llmBanner.className = "llm-banner error";
    llmBanner.textContent = `OpenAI review failed: ${event.message}`;
  } else if (event.type === "llm-skipped") {
    updateLlmBanner();
  }
}

function updateLlmBanner() {
  if (state.settings.configured) {
    llmBanner.hidden = false;
    llmBanner.className = "llm-banner";
    llmBanner.textContent = `AI review on · ${state.settings.model} (security + quality)`;
  } else {
    llmBanner.hidden = false;
    llmBanner.className = "llm-banner";
    llmBanner.textContent = "Heuristic scan is on. Add an OpenAI key in Settings for a second pass on each page.";
  }
}

function connectEvents() {
  const source = new EventSource("/api/events");
  source.onmessage = (msg) => {
    try {
      applyEvent(JSON.parse(msg.data));
    } catch {
      /* ignore */
    }
  };
}

document.getElementById("nav-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (!urlInput.value.trim()) return;
  browse(urlInput.value);
});
document.getElementById("open-lab").addEventListener("click", () => browse(labUrl()));
document.getElementById("back").addEventListener("click", () => {
  try {
    view.contentWindow.history.back();
  } catch {
    /* ignore */
  }
});
document.getElementById("forward").addEventListener("click", () => {
  try {
    view.contentWindow.history.forward();
  } catch {
    /* ignore */
  }
});
document.getElementById("reload").addEventListener("click", () => {
  if (!urlInput.value.trim()) return;
  browse(urlInput.value);
});
document.getElementById("reset").addEventListener("click", async () => {
  await fetch("/api/reset", { method: "POST" });
  showIdle();
});
document.getElementById("view-page").addEventListener("click", () => {
  state.view = "page";
  renderAll();
});
document.getElementById("view-session").addEventListener("click", () => {
  state.view = "session";
  renderAll();
});
document.getElementById("tab-findings").addEventListener("click", () => setPanel("findings"));
document.getElementById("tab-quality").addEventListener("click", () => setPanel("quality"));
document.getElementById("tab-inventory").addEventListener("click", () => setPanel("inventory"));
document.getElementById("scope-add").addEventListener("click", async () => {
  const pending = state.pendingScope;
  if (!pending) return;
  hideScopePrompt();
  await addScopeHost(pending.host);
  loadFrame(pending.url);
});
document.getElementById("scope-dismiss").addEventListener("click", () => {
  hideScopePrompt();
});
openFixes.addEventListener("click", async () => {
  const local = buildOverallPlan(state.view, visiblePages().length > 0);
  state.plan = local;
  renderFixes(local, state.settings.configured ? "Checking OpenAI for a tighter overall plan…" : "");
  fixesDlg.showModal();
  if (!state.settings.configured) return;
  try {
    const result = await fetch("/api/plan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        kind: "overall",
        llm: true,
        page: state.view === "page" ? state.currentUrl : "",
      }),
    }).then((res) => res.json());
    if (!fixesDlg.open) return;
    if (result.llmError) {
      renderFixes({ ...local, ...result, layman: result.layman || local.layman, agentPrompt: result.agentPrompt || local.agentPrompt, fixes: result.fixes || local.fixes }, result.llmError);
      return;
    }
    state.plan = { ...local, ...result };
    renderFixes(state.plan, result.source === "openai" ? `Plan written by ${result.model || "OpenAI"}.` : "");
  } catch (err) {
    if (fixesDlg.open) renderFixes(local, err.message || "Could not reach the planner.");
  }
});
document.getElementById("copy-fixes").addEventListener("click", async () => {
  const plan = state.plan || buildOverallPlan(state.view, visiblePages().length > 0);
  const text = [
    plan.layman || "",
    "",
    `BrowseAudit · Grade ${plan.grade && plan.grade.letter ? plan.grade.letter : "—"} · ${plan.risk}`,
    plan.summary,
    "",
    ...plan.fixes.map((item, index) => `${index + 1}. [${item.lane || "security"} / ${item.severity}] ${item.title}\n   ${item.do}`),
  ]
    .join("\n")
    .trim();
  try {
    await navigator.clipboard.writeText(text);
    document.getElementById("fixes-status").textContent = "Copied.";
  } catch {
    document.getElementById("fixes-status").textContent = "Copy failed.";
  }
});
document.getElementById("copy-agent").addEventListener("click", async () => {
  const plan = state.plan || buildOverallPlan(state.view, visiblePages().length > 0);
  try {
    await navigator.clipboard.writeText(plan.agentPrompt || "");
    document.getElementById("fixes-status").textContent = "Agent prompt copied.";
  } catch {
    document.getElementById("fixes-status").textContent = "Copy failed.";
  }
});
exportReport.addEventListener("click", async () => {
  exportReport.disabled = true;
  const original = exportReport.textContent;
  exportReport.textContent = state.settings.configured ? "Writing…" : "Exporting…";
  try {
    const result = await fetch("/api/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        llm: Boolean(state.settings.configured),
        page: state.view === "page" ? state.currentUrl : "",
      }),
    }).then((res) => res.json());
    if (!result.markdown) return;
    const blob = new Blob([result.markdown], { type: "text/markdown;charset=utf-8" });
    const href = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = href;
    link.download = result.filename || "browseaudit-report.md";
    link.click();
    URL.revokeObjectURL(href);
    if (result.llmError) llmBanner.textContent = `Report used local checks: ${result.llmError}`;
  } catch {
    llmBanner.hidden = false;
    llmBanner.className = "llm-banner error";
    llmBanner.textContent = "Could not export the report.";
  } finally {
    exportReport.textContent = original;
    exportReport.disabled = false;
  }
});
filtersEl.addEventListener("click", (event) => {
  const btn = event.target.closest("button[data-filter]");
  if (!btn) return;
  state.filter = btn.dataset.filter;
  renderFilters();
  renderFindings();
});
qualityFiltersEl.addEventListener("click", (event) => {
  const btn = event.target.closest("button[data-filter]");
  if (!btn) return;
  state.qualityFilter = btn.dataset.filter;
  renderQualityFilters();
  renderQuality();
});
openImprovements.addEventListener("click", async () => {
  const local = buildQualityPlan(
    visibleQualityFindings(),
    visibleSummaries("quality"),
    state.view,
    visiblePages().length > 0
  );
  state.qualityPlan = local;
  renderImprovements(local, state.settings.configured ? "Checking OpenAI for a tighter plan…" : "");
  improvementsDlg.showModal();
  if (!state.settings.configured) return;
  try {
    const result = await fetch("/api/plan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        kind: "quality",
        llm: true,
        page: state.view === "page" ? state.currentUrl : "",
      }),
    }).then((res) => res.json());
    if (!improvementsDlg.open) return;
    if (result.llmError) {
      renderImprovements(local, result.llmError);
      return;
    }
    state.qualityPlan = result;
    renderImprovements(result, result.source === "openai" ? `Plan written by ${result.model || "OpenAI"}.` : "");
  } catch (err) {
    if (improvementsDlg.open) renderImprovements(local, err.message || "Could not reach the planner.");
  }
});
document.getElementById("copy-improvements").addEventListener("click", async () => {
  const plan =
    state.qualityPlan ||
    buildQualityPlan(visibleQualityFindings(), visibleSummaries("quality"), state.view, visiblePages().length > 0);
  const text = [
    `BrowseAudit · Quality ${plan.score && plan.score.label ? plan.score.label : "—"}`,
    plan.summary,
    "",
    ...plan.fixes.map((item, index) => `${index + 1}. [${item.severity}] ${item.title}\n   ${item.do}`),
  ].join("\n");
  try {
    await navigator.clipboard.writeText(text);
    document.getElementById("improvements-status").textContent = "Copied.";
  } catch {
    document.getElementById("improvements-status").textContent = "Copy failed.";
  }
});
document.getElementById("network-toggle").addEventListener("click", () => {
  networkEl.hidden = !networkEl.hidden;
});

window.addEventListener("message", (event) => {
  if (!event.data || typeof event.data !== "object") return;
  if (event.data.type === "browseaudit:intent" && event.data.intent) {
    fetch("/api/quality", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: event.data.url || state.currentUrl, intent: event.data.intent }),
    }).catch(() => {});
  }
  if (event.data.type === "browseaudit:client-nav") {
    fetch("/api/quality", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: event.data.href || event.data.url || state.currentUrl, clientNav: true }),
    }).catch(() => {});
  }
  if (event.data.type === "browseaudit:nav" && event.data.href) {
    urlInput.value = event.data.href;
    pageTitle.textContent = event.data.href;
    state.currentUrl = event.data.href;
    lock.textContent = event.data.href.startsWith("https:") ? "HTTPS" : "HTTP";
    lock.classList.toggle("secure", event.data.href.startsWith("https:"));
    renderAll();
  }
});

view.addEventListener("load", () => {
  if (!emptyEl.hidden) return;
  const current = fromFrameLocation();
  if (!current || current === "about:blank") return;
  urlInput.value = current;
  pageTitle.textContent = current;
  state.currentUrl = current;
  renderAll();
});

document.getElementById("open-settings").addEventListener("click", async () => {
  const settings = await fetch("/api/settings").then((r) => r.json());
  state.settings = settings;
  document.getElementById("api-key").value = "";
  document.getElementById("api-key").placeholder = settings.configured ? "Key saved on this machine" : "sk-…";
  document.getElementById("model").value = settings.model || "gpt-4o-mini";
  document.getElementById("base-url").value = settings.baseUrl || "";
  document.getElementById("settings-status").textContent = settings.configured
    ? "A key is already saved. Leave the field blank to keep it."
    : "No key saved yet.";
  settingsDlg.showModal();
});

document.getElementById("settings-form").addEventListener("submit", async (event) => {
  if (event.submitter && event.submitter.value === "cancel") return;
  event.preventDefault();
  const body = {
    model: document.getElementById("model").value.trim(),
    baseUrl: document.getElementById("base-url").value.trim(),
  };
  const key = document.getElementById("api-key").value.trim();
  if (key) body.apiKey = key;
  const settings = await fetch("/api/settings", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then((r) => r.json());
  state.settings = settings;
  document.getElementById("settings-status").textContent = settings.configured ? "Saved." : "Saved without a key.";
  document.getElementById("api-key").value = "";
  updateLlmBanner();
});

document.getElementById("test-key").addEventListener("click", async () => {
  const key = document.getElementById("api-key").value.trim();
  if (key) {
    await fetch("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        apiKey: key,
        model: document.getElementById("model").value.trim(),
        baseUrl: document.getElementById("base-url").value.trim(),
      }),
    });
  }
  const result = await fetch("/api/settings/test", { method: "POST" }).then((r) => r.json());
  document.getElementById("settings-status").textContent = result.ok
    ? `Connected (${result.model})`
    : result.error || "Test failed";
});

document.getElementById("clear-key").addEventListener("click", async () => {
  const settings = await fetch("/api/settings", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ clearKey: true }),
  }).then((r) => r.json());
  state.settings = settings;
  document.getElementById("settings-status").textContent = "Key removed.";
  updateLlmBanner();
});

fetch("/api/reset", { method: "POST" })
  .catch(() => {})
  .finally(() => {
    connectEvents();
    showIdle();
  });
