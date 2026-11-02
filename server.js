const http = require("http");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");
const { Session } = require("./lib/session");
const { CookieJar } = require("./lib/cookies");
const { analyzePage, analyzeDom, buildSnapshot } = require("./lib/analyze");
const {
  analyzeQualityHtml,
  analyzeQualityDom,
  analyzeQualityNavigation,
  qualityFailureFromRequest,
} = require("./lib/quality");
const { rewriteHtml, rewriteCss, rewriteLocation } = require("./lib/rewrite");
const { fromProxyPath, isBlockedTarget, publicOrigin, samePage, isLabTarget } = require("./lib/urls");
const llm = require("./lib/llm");
const { buildPlan, buildQualityPlan } = require("./lib/plan");
const { buildReport, overallFromSession } = require("./lib/report");
const { pageInventory } = require("./lib/inventory");
const { allowProxy, outOfScopeHtml } = require("./lib/scope");

const PORT = Number(process.env.PORT) || 8790;
const PUBLIC_DIR = path.join(__dirname, "public");
const LAB_DIR = path.join(__dirname, "lab");
const MAX_BODY = 8 * 1024 * 1024;

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
  ".ico": "image/x-icon",
  ".png": "image/png",
  ".woff2": "font/woff2",
};

const session = new Session();
const cookies = new CookieJar();
const sseClients = new Set();
const llmTimers = new Map();

session.on("event", (event) => broadcast(event));

function broadcast(event) {
  const payload = `data: ${JSON.stringify(event)}\n\n`;
  for (const res of sseClients) res.write(payload);
}

function send(res, status, headers, body) {
  res.writeHead(status, headers);
  res.end(body);
}

function sendJson(res, status, data) {
  send(res, status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }, JSON.stringify(data));
}

function readBody(req, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function safeJoin(root, reqPath) {
  const rel = decodeURIComponent(reqPath.split("?")[0]).replace(/^\/+/, "");
  const resolved = path.resolve(root, rel);
  if (!resolved.startsWith(root)) return null;
  return resolved;
}

function serveStatic(res, filePath, extraHeaders = {}) {
  fs.stat(filePath, (err, stat) => {
    if (err || !stat.isFile()) {
      send(res, 404, { "Content-Type": "text/plain" }, "Not found");
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    send(
      res,
      200,
      {
        "Content-Type": MIME[ext] || "application/octet-stream",
        "Cache-Control": "no-store",
        ...extraHeaders,
      },
      fs.readFileSync(filePath)
    );
  });
}

function labHeaders() {
  return {
    "X-Powered-By": "PHP/5.4.16",
    Server: "Apache/2.2.22 (Ubuntu)",
    "Set-Cookie": ["sessionid=lab-demo-session", "tracking=1; SameSite=None"],
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  };
}

function isDocumentRequest(req) {
  const dest = String(req.headers["sec-fetch-dest"] || "").toLowerCase();
  if (!dest) return true;
  return dest === "document" || dest === "iframe" || dest === "frame" || dest === "embed" || dest === "object";
}

function scheduleLlm(pageUrl) {
  if (llmTimers.has(pageUrl)) clearTimeout(llmTimers.get(pageUrl));
  const timer = setTimeout(() => {
    llmTimers.delete(pageUrl);
    runLlm(pageUrl).catch((err) => {
      broadcast({ type: "llm-error", url: pageUrl, message: err.message || String(err) });
    });
  }, 900);
  llmTimers.set(pageUrl, timer);
}

async function runLlm(pageUrl) {
  const snapshot = session.snapshots.get(pageUrl);
  if (!snapshot) return;
  if (!llm.publicSettings().configured) {
    broadcast({ type: "llm-skipped", url: pageUrl, reason: "not_configured" });
    return;
  }
  broadcast({ type: "llm-start", url: pageUrl });
  const already = session.findings.filter((item) => samePage(item.url, pageUrl) && item.source !== "openai");
  const securityAlready = already.filter((item) => item.lane !== "quality");
  const qualityAlready = already.filter((item) => item.lane === "quality");
  const settled = await Promise.allSettled([
    llm.reviewSnapshot(snapshot, securityAlready),
    llm.reviewQuality(snapshot, qualityAlready),
  ]);
  const security = settled[0].status === "fulfilled" ? settled[0].value : null;
  const quality = settled[1].status === "fulfilled" ? settled[1].value : null;
  if (security) {
    session.addFindings(security.findings, pageUrl);
    if (security.summary) {
      session.addLlmSummary({ url: pageUrl, text: security.summary, model: security.model, kind: "security" });
    }
  }
  if (quality) {
    session.addFindings(quality.findings, pageUrl);
    if (quality.summary) {
      session.addLlmSummary({ url: pageUrl, text: quality.summary, model: quality.model, kind: "quality" });
    }
  }
  const model = (security && security.model) || (quality && quality.model) || "";
  const count = (security ? security.findings.length : 0) + (quality ? quality.findings.length : 0);
  if (!security && !quality) {
    const err = settled[0].reason || settled[1].reason;
    broadcast({ type: "llm-error", url: pageUrl, message: (err && err.message) || "OpenAI review failed" });
    return;
  }
  broadcast({
    type: "llm-done",
    url: pageUrl,
    summary: (security && security.summary) || "",
    qualitySummary: (quality && quality.summary) || "",
    model,
    count,
    qualityCount: quality ? quality.findings.length : 0,
  });
  if (settled[0].status === "rejected" || settled[1].status === "rejected") {
    const err = settled[0].status === "rejected" ? settled[0].reason : settled[1].reason;
    broadcast({ type: "llm-error", url: pageUrl, message: (err && err.message) || "One OpenAI pass failed" });
  }
}

function recordPage(pageUrl, status, headers, setCookies, html) {
  session.currentPageUrl = pageUrl;
  const nav = session.consumeNavigation(pageUrl);
  session.addFindings(analyzePage(pageUrl, status, headers, setCookies, html), pageUrl);
  session.addFindings(analyzeQualityHtml(pageUrl, html, status), pageUrl);
  session.addFindings(analyzeQualityNavigation(nav), pageUrl);
  session.rememberSnapshot(pageUrl, buildSnapshot(pageUrl, status, headers, setCookies, html));
  session.rememberPage(pageInventory(pageUrl, status, headers, setCookies));
  broadcast({ type: "navigation", url: pageUrl, status, counts: session.snapshot().counts });
  scheduleLlm(pageUrl);
}

function noteFailedResource(request) {
  const finding = qualityFailureFromRequest(request, session.currentPageUrl);
  if (finding) session.addFindings([finding], session.currentPageUrl);
}

async function handleProxy(req, res, targetUrl) {
  const blocked = isBlockedTarget(targetUrl);
  if (blocked) {
    sendJson(res, 400, { error: blocked });
    return;
  }

  const scopeGate = allowProxy(req, targetUrl, session);
  if (!scopeGate.ok) {
    broadcast({ type: "out-of-scope", url: targetUrl, host: scopeGate.host, reason: scopeGate.reason });
    send(res, 403, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }, outOfScopeHtml(scopeGate));
    return;
  }

  const origin = publicOrigin(req);
  const started = Date.now();
  const incoming = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (!value) continue;
    const lower = key.toLowerCase();
    if (["host", "connection", "content-length", "accept-encoding", "cookie", "origin", "referer"].includes(lower)) continue;
    incoming.set(key, Array.isArray(value) ? value.join(",") : value);
  }
  incoming.set("Accept-Encoding", "identity");
  const cookieHeader = cookies.header(targetUrl);
  if (cookieHeader) incoming.set("Cookie", cookieHeader);

  let body;
  if (req.method !== "GET" && req.method !== "HEAD") {
    body = await readBody(req, MAX_BODY);
  }

  let upstream;
  try {
    upstream = await fetch(targetUrl, {
      method: req.method,
      headers: incoming,
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(20000),
    });
  } catch (err) {
    const request = session.addRequest({
      method: req.method,
      url: targetUrl,
      status: 0,
      type: "error",
      ms: Date.now() - started,
    });
    if (isDocumentRequest(req)) {
      session.currentPageUrl = targetUrl;
      session.addFindings(analyzeQualityHtml(targetUrl, "", 0), targetUrl);
    } else {
      noteFailedResource(request);
    }
    send(
      res,
      502,
      { "Content-Type": "text/html; charset=utf-8" },
      `<!doctype html><meta charset="utf-8"><title>Proxy error</title><body style="font:16px system-ui;background:#0b1220;color:#e8eef8;padding:2rem"><h1>Could not load this page</h1><p>${escapeHtml(err.message)}</p></body>`
    );
    return;
  }

  const headerObj = {};
  upstream.headers.forEach((value, key) => {
    headerObj[key] = value;
  });
  const setCookieHeaders =
    typeof upstream.headers.getSetCookie === "function"
      ? upstream.headers.getSetCookie()
      : headerObj["set-cookie"];
  const setCookies = cookies.remember(setCookieHeaders, targetUrl);
  const contentType = (upstream.headers.get("content-type") || "").toLowerCase();
  const location = upstream.headers.get("location");

  const outHeaders = {};
  upstream.headers.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (
      [
        "x-frame-options",
        "content-security-policy",
        "content-security-policy-report-only",
        "content-encoding",
        "content-length",
        "set-cookie",
        "transfer-encoding",
        "location",
        "report-to",
        "nel",
        "clear-site-data",
      ].includes(lower)
    ) {
      return;
    }
    outHeaders[key] = value;
  });
  outHeaders["Cache-Control"] = "no-store";
  outHeaders["X-Browseaudit-Url"] = targetUrl;

  if (location) {
    outHeaders.Location = rewriteLocation(location, targetUrl, origin);
  }

  const isHtml = contentType.includes("text/html") || contentType.includes("application/xhtml");
  const isCss = contentType.includes("text/css");
  const documentHtml = isHtml && isDocumentRequest(req);
  if (documentHtml) session.currentPageUrl = targetUrl;
  const request = session.addRequest({
    method: req.method,
    url: targetUrl,
    status: upstream.status,
    type: isHtml ? "document" : contentType.split(";")[0],
    ms: Date.now() - started,
  });
  if (!documentHtml) noteFailedResource(request);

  if (isHtml) {
    const html = await upstream.text();
    if (isDocumentRequest(req)) {
      if (session.inScopeUrl(targetUrl) || isLabTarget(targetUrl, req)) {
        recordPage(targetUrl, upstream.status, headerObj, setCookies, html);
      }
      const rewritten = rewriteHtml(html, targetUrl, origin);
      outHeaders["Content-Type"] = "text/html; charset=utf-8";
      send(res, upstream.status, outHeaders, rewritten);
      return;
    }
    outHeaders["Content-Type"] = contentType || "text/html; charset=utf-8";
    send(res, upstream.status, outHeaders, html);
    return;
  }

  if (isCss) {
    const css = await upstream.text();
    const rewritten = rewriteCss(css, targetUrl, origin);
    outHeaders["Content-Type"] = "text/css; charset=utf-8";
    send(res, upstream.status, outHeaders, rewritten);
    return;
  }

  const buffer = Buffer.from(await upstream.arrayBuffer());
  outHeaders["Content-Length"] = String(buffer.length);
  send(res, upstream.status, outHeaders, buffer);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

async function handleApi(req, res, url) {
  if (url.pathname === "/api/events") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-store",
      Connection: "keep-alive",
    });
    res.write(`data: ${JSON.stringify({ type: "hello", ...session.snapshot(), settings: llm.publicSettings() })}\n\n`);
    sseClients.add(res);
    req.on("close", () => sseClients.delete(res));
    return;
  }

  if (url.pathname === "/api/snapshot" && req.method === "GET") {
    sendJson(res, 200, { ...session.snapshot(), settings: llm.publicSettings() });
    return;
  }

  if (url.pathname === "/api/reset" && req.method === "POST") {
    cookies.clear();
    session.reset();
    sendJson(res, 200, { ok: true });
    return;
  }

  if (url.pathname === "/api/settings" && req.method === "GET") {
    sendJson(res, 200, llm.publicSettings());
    return;
  }

  if (url.pathname === "/api/settings" && req.method === "PUT") {
    let body = {};
    try {
      body = JSON.parse((await readBody(req)).toString("utf8") || "{}");
    } catch {
      sendJson(res, 400, { error: "Invalid JSON" });
      return;
    }
    sendJson(res, 200, llm.saveSettings(body));
    return;
  }

  if (url.pathname === "/api/scope" && req.method === "GET") {
    sendJson(res, 200, { hosts: session.scopeList(), labAllowed: true });
    return;
  }

  if (url.pathname === "/api/scope" && req.method === "PUT") {
    let body = {};
    try {
      body = JSON.parse((await readBody(req)).toString("utf8") || "{}");
    } catch {
      sendJson(res, 400, { error: "Invalid JSON" });
      return;
    }
    if (Array.isArray(body.hosts)) session.replaceScope(body.hosts);
    if (body.add) session.addScope(body.add);
    if (body.remove) session.removeScope(body.remove);
    const hosts = session.scopeList();
    broadcast({ type: "scope", hosts });
    sendJson(res, 200, { hosts, labAllowed: true });
    return;
  }

  if (url.pathname === "/api/report" && (req.method === "GET" || req.method === "POST")) {
    let page = url.searchParams.get("page") || "";
    let wantLlm = url.searchParams.get("llm") === "1";
    if (req.method === "POST") {
      let body = {};
      try {
        body = JSON.parse((await readBody(req)).toString("utf8") || "{}");
      } catch {
        body = {};
      }
      if (body.page) page = body.page;
      if (body.llm) wantLlm = true;
    }
    const packed = overallFromSession(session, { page });
    let brief = null;
    let source = "heuristic";
    let model = "";
    let llmError = "";
    if (wantLlm && llm.publicSettings().configured) {
      try {
        brief = await llm.writeBrief(packed.overall);
        source = "openai";
        model = brief.model || "";
      } catch (err) {
        llmError = err.message || String(err);
      }
    }
    const markdown = buildReport(session, { page, brief, source, model });
    if (req.method === "POST") {
      sendJson(res, 200, { markdown, source, model, llmError: llmError || undefined, filename: "browseaudit-report.md" });
      return;
    }
    send(
      res,
      200,
      {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Disposition": 'attachment; filename="browseaudit-report.md"',
        "Cache-Control": "no-store",
      },
      markdown
    );
    return;
  }

  if (url.pathname === "/api/plan" && req.method === "POST") {
    let body = {};
    try {
      body = JSON.parse((await readBody(req)).toString("utf8") || "{}");
    } catch {
      body = {};
    }
    const page = body.page || "";
    const kind = body.kind === "quality" ? "quality" : body.kind === "security" ? "security" : "overall";
    const reviewed = page ? Boolean(session.pageFor(page)) : session.pages.size > 0;
    const view = page ? "page" : "session";
    let heuristic;
    if (kind === "quality") {
      const findings = session.findingsFor(page, "quality");
      const summaries = (page
        ? session.llmSummaries.filter((item) => samePage(item.url, page))
        : session.llmSummaries
      ).filter((item) => item.kind === "quality");
      heuristic = buildQualityPlan(findings, summaries, { view, reviewed });
    } else if (kind === "security") {
      const findings = session.findingsFor(page, "security");
      const summaries = (page
        ? session.llmSummaries.filter((item) => samePage(item.url, page))
        : session.llmSummaries
      ).filter((item) => (item.kind || "security") !== "quality");
      heuristic = buildPlan(findings, summaries, { view, reviewed });
    } else {
      heuristic = overallFromSession(session, { page }).overall;
    }
    if (!body.llm || !llm.publicSettings().configured) {
      sendJson(res, 200, { ...heuristic, source: "heuristic" });
      return;
    }
    try {
      const refined =
        kind === "quality"
          ? await llm.writeQualityPlan(heuristic)
          : kind === "security"
            ? await llm.writeFixPlan(heuristic)
            : await llm.writeBrief(heuristic);
      sendJson(res, 200, { ...heuristic, ...refined, source: "openai" });
    } catch (err) {
      sendJson(res, 200, { ...heuristic, source: "heuristic", llmError: err.message });
    }
    return;
  }

  if (url.pathname === "/api/settings/test" && req.method === "POST") {
    try {
      sendJson(res, 200, await llm.testConnection());
    } catch (err) {
      sendJson(res, 400, { ok: false, error: err.message });
    }
    return;
  }

  if (url.pathname === "/api/dom" && req.method === "POST") {
    let body = {};
    try {
      body = JSON.parse((await readBody(req)).toString("utf8") || "{}");
    } catch {
      sendJson(res, 400, { error: "Invalid JSON" });
      return;
    }
    const pageUrl = body.url;
    if (!pageUrl) {
      sendJson(res, 400, { error: "url required" });
      return;
    }
    if (!session.inScopeUrl(pageUrl) && !isLabTarget(pageUrl, req)) {
      sendJson(res, 403, { error: "out-of-scope" });
      return;
    }
    session.addFindings(analyzeDom(pageUrl, body.dom), pageUrl);
    session.addFindings(analyzeQualityDom(pageUrl, body.quality || body.dom), pageUrl);
    const snapshot = session.snapshots.get(pageUrl) || buildSnapshot(pageUrl, 200, {}, [], "");
    snapshot.runtime = body.dom;
    snapshot.quality = body.quality || null;
    session.rememberSnapshot(pageUrl, snapshot);
    scheduleLlm(pageUrl);
    sendJson(res, 200, { ok: true });
    return;
  }

  if (url.pathname === "/api/quality" && req.method === "POST") {
    let body = {};
    try {
      body = JSON.parse((await readBody(req)).toString("utf8") || "{}");
    } catch {
      sendJson(res, 400, { error: "Invalid JSON" });
      return;
    }
    const pageUrl = body.url || "";
    if (!pageUrl) {
      sendJson(res, 400, { error: "url required" });
      return;
    }
    if (!session.inScopeUrl(pageUrl) && !isLabTarget(pageUrl, req)) {
      sendJson(res, 403, { error: "out-of-scope" });
      return;
    }
    if (body.intent) session.noteIntent({ ...body.intent, from: body.intent.from || pageUrl });
    if (body.clientNav) session.noteClientNav(pageUrl);
    if (body.fullReload) {
      session.addFindings(analyzeQualityDom(pageUrl, { fullReloads: [body.fullReload] }), body.fullReload.to || body.fullReload.href || pageUrl);
    }
    sendJson(res, 200, { ok: true });
    return;
  }

  sendJson(res, 404, { error: "not found" });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || "127.0.0.1"}`);

    if (url.pathname.startsWith("/proxy/")) {
      const target = fromProxyPath(req.url);
      if (!target) {
        sendJson(res, 400, { error: "Invalid proxy URL" });
        return;
      }
      await handleProxy(req, res, target);
      return;
    }

    if (url.pathname.startsWith("/api/")) {
      await handleApi(req, res, url);
      return;
    }

    if (url.pathname === "/probe.js") {
      serveStatic(res, path.join(PUBLIC_DIR, "probe.js"), {
        "Cache-Control": "no-store",
        "Content-Type": "text/javascript; charset=utf-8",
      });
      return;
    }

    if (url.pathname.startsWith("/lab")) {
      let rel = url.pathname.slice("/lab".length) || "/";
      if (rel === "/") rel = "/index.html";
      const filePath = safeJoin(LAB_DIR, rel);
      if (!filePath || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
        send(res, 404, labHeaders(), "<h1>Lab page not found</h1>");
        return;
      }
      const html = fs.readFileSync(filePath);
      const headers = labHeaders();
      if (path.extname(filePath) !== ".html") {
        headers["Content-Type"] = MIME[path.extname(filePath)] || "text/plain";
        delete headers["Set-Cookie"];
      }
      send(res, 200, headers, html);
      return;
    }

    if (url.pathname === "/" || url.pathname === "/index.html") {
      serveStatic(res, path.join(PUBLIC_DIR, "index.html"), {
        "Content-Security-Policy":
          "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src 'self'; font-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "SAMEORIGIN",
      });
      return;
    }

    if (url.pathname.startsWith("/assets/")) {
      const filePath = safeJoin(path.join(__dirname, "assets"), url.pathname.slice("/assets".length));
      if (filePath) {
        serveStatic(res, filePath);
        return;
      }
    }

    const filePath = safeJoin(PUBLIC_DIR, url.pathname);
    if (filePath && fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      serveStatic(res, filePath);
      return;
    }

    send(res, 404, { "Content-Type": "text/plain" }, "Not found");
  } catch (err) {
    if (!res.headersSent) sendJson(res, 500, { error: err.message || "server error" });
    else res.end();
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`BrowseAudit running at http://127.0.0.1:${PORT}`);
});
