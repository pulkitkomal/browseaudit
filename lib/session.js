const { EventEmitter } = require("events");
const { gradeFromFindings } = require("./grade");
const { qualityScore } = require("./quality");
const { hostOf, normalizeHost, samePage } = require("./urls");

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

class Session extends EventEmitter {
  constructor() {
    super();
    this.findings = [];
    this.requests = [];
    this.seen = new Set();
    this.snapshots = new Map();
    this.llmPending = new Map();
    this.llmSummaries = [];
    this.pages = new Map();
    this.scopeHosts = new Set();
    this.currentPageUrl = "";
    this.lastDocumentUrl = "";
    this.pendingIntent = null;
    this.clientNavHosts = new Set();
  }

  reset() {
    this.findings = [];
    this.requests = [];
    this.seen.clear();
    this.snapshots.clear();
    this.llmPending.clear();
    this.llmSummaries = [];
    this.pages.clear();
    this.scopeHosts.clear();
    this.currentPageUrl = "";
    this.lastDocumentUrl = "";
    this.pendingIntent = null;
    this.clientNavHosts.clear();
    this.emit("event", { type: "reset" });
  }

  noteIntent(intent) {
    if (!intent || !intent.kind) return;
    this.pendingIntent = {
      kind: intent.kind === "app-nav" ? "app-nav" : "tab",
      label: String(intent.label || intent.text || "").slice(0, 80),
      href: String(intent.href || "").slice(0, 300),
      from: String(intent.from || this.currentPageUrl || "").slice(0, 300),
      at: Date.now(),
    };
  }

  noteClientNav(url) {
    const host = hostOf(url || this.currentPageUrl);
    if (host) this.clientNavHosts.add(host);
    this.pendingIntent = null;
  }

  consumeNavigation(pageUrl) {
    const intent =
      this.pendingIntent && Date.now() - this.pendingIntent.at < 8000 ? this.pendingIntent : null;
    const context = {
      from: this.lastDocumentUrl,
      to: pageUrl,
      intent,
      clientNav: this.clientNavHosts.has(hostOf(pageUrl)),
    };
    this.lastDocumentUrl = pageUrl || this.lastDocumentUrl;
    this.pendingIntent = null;
    return context;
  }

  addFinding(raw, pageUrl) {
    if (!raw || !raw.title) return null;
    const finding = {
      id: raw.id || raw.title,
      severity: SEVERITY_RANK[raw.severity] != null ? raw.severity : "info",
      title: String(raw.title).slice(0, 160),
      description: String(raw.description || "").slice(0, 800),
      evidence: String(raw.evidence || "").slice(0, 400),
      recommendation: String(raw.recommendation || "").slice(0, 600),
      category: raw.category || "general",
      cwe: raw.cwe || "",
      source: raw.source || "heuristic",
      confidence: raw.confidence || "high",
      lane: raw.lane === "quality" ? "quality" : "security",
      url: pageUrl || raw.url || "",
      at: Date.now(),
    };
    const key = `${finding.id}|${finding.url}|${finding.evidence}|${finding.source}`;
    if (this.seen.has(key)) return null;
    this.seen.add(key);
    this.findings.unshift(finding);
    if (this.findings.length > 400) this.findings.pop();
    this.emit("event", { type: "finding", finding });
    return finding;
  }

  addFindings(list, pageUrl) {
    return (list || []).map((item) => this.addFinding(item, pageUrl)).filter(Boolean);
  }

  addRequest(entry) {
    const request = {
      method: entry.method || "GET",
      url: entry.url,
      status: entry.status || 0,
      type: entry.type || "",
      ms: entry.ms || 0,
      at: Date.now(),
    };
    this.requests.unshift(request);
    if (this.requests.length > 200) this.requests.pop();
    this.emit("event", { type: "request", request });
    return request;
  }

  rememberSnapshot(url, snapshot) {
    this.snapshots.set(url, snapshot);
  }

  rememberPage(page) {
    if (!page || !page.url) return null;
    this.currentPageUrl = page.url;
    this.pages.delete(page.url);
    this.pages.set(page.url, page);
    this.emit("event", { type: "page", page });
    return page;
  }

  pageList() {
    return [...this.pages.values()].reverse();
  }

  pageFor(url) {
    if (!url) return null;
    if (this.pages.has(url)) return this.pages.get(url);
    for (const page of this.pages.values()) {
      if (samePage(page.url, url)) return page;
    }
    return null;
  }

  addLlmSummary(entry) {
    if (!entry || !entry.text) return;
    const kind = entry.kind === "quality" ? "quality" : "security";
    this.llmSummaries = this.llmSummaries.filter((item) => !(item.url === entry.url && (item.kind || "security") === kind));
    this.llmSummaries.unshift({
      url: entry.url || "",
      text: String(entry.text).slice(0, 600),
      model: entry.model || "",
      kind,
    });
  }

  hasScope() {
    return this.scopeHosts.size > 0;
  }

  inScope(host) {
    const normalized = normalizeHost(host);
    if (!normalized) return false;
    if (this.scopeHosts.has(normalized)) return true;
    const hostname = normalized.split(":")[0];
    return this.scopeHosts.has(hostname);
  }

  inScopeUrl(targetUrl) {
    return this.inScope(hostOf(targetUrl));
  }

  scopeList() {
    return [...this.scopeHosts];
  }

  addScope(value) {
    const host = normalizeHost(value);
    if (!host) return this.scopeList();
    this.scopeHosts.add(host);
    return this.scopeList();
  }

  removeScope(value) {
    const host = normalizeHost(value);
    this.scopeHosts.delete(host);
    this.scopeHosts.delete(host.split(":")[0]);
    return this.scopeList();
  }

  replaceScope(hosts) {
    this.scopeHosts.clear();
    for (const value of hosts || []) this.addScope(value);
    return this.scopeList();
  }

  findingsFor(pageUrl, lane) {
    let list = pageUrl ? this.findings.filter((item) => samePage(item.url, pageUrl)) : this.findings;
    if (lane === "quality") return list.filter((item) => item.lane === "quality");
    if (lane === "security") return list.filter((item) => item.lane !== "quality");
    return list;
  }

  snapshot() {
    const pages = this.pageList();
    const security = this.findingsFor("", "security");
    const quality = this.findingsFor("", "quality");
    return {
      findings: this.findings,
      requests: this.requests,
      counts: countBySeverity(security),
      grade: gradeFromFindings(security, { reviewed: pages.length > 0 }),
      quality: qualityScore(quality, { reviewed: pages.length > 0 }),
      scope: this.scopeList(),
      pages,
      llmSummaries: this.llmSummaries,
    };
  }
}

function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    if (counts[finding.severity] != null) counts[finding.severity] += 1;
  }
  return counts;
}

module.exports = { Session, SEVERITY_RANK, countBySeverity };
