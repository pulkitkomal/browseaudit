const { hostOf, isLabTarget, normalizeHost } = require("./urls");

function looksLikeDocument(req) {
  const dest = String(req.headers["sec-fetch-dest"] || "").toLowerCase();
  if (dest === "document" || dest === "iframe" || dest === "frame" || dest === "embed" || dest === "object") {
    return true;
  }
  if (dest) return false;
  const accept = String(req.headers.accept || "").toLowerCase();
  return accept.includes("text/html");
}

function allowProxy(req, targetUrl, session) {
  if (isLabTarget(targetUrl, req)) return { ok: true, lab: true };
  const host = hostOf(targetUrl);
  if (!host) return { ok: false, reason: "The URL could not be parsed.", host: "" };
  if (session.inScope(host)) return { ok: true, host };
  if (!looksLikeDocument(req) && session.hasScope()) return { ok: true, host, subresource: true };
  if (!session.hasScope()) {
    return { ok: false, reason: "no-scope", host };
  }
  return { ok: false, reason: "out-of-scope", host };
}

function outOfScopeHtml(gate) {
  const host = escapeHtml(gate.host || "");
  const reason =
    gate.reason === "no-scope"
      ? "Open a URL from the BrowseAudit bar first. That host becomes the session scope."
      : `${host || "This host"} is outside the current session scope. Add it from the findings panel if you intend to review it.`;
  return `<!doctype html><meta charset="utf-8"><title>Out of scope</title>
<body style="font:16px/1.45 system-ui,sans-serif;background:#0b1220;color:#e8eef8;padding:2rem;max-width:36rem">
<h1 style="font-size:1.2rem">Host is out of scope</h1>
<p>${reason}</p>
<p style="color:#8aa0b8">BrowseAudit only loads documents for hosts you have scoped, plus the local lab. Subresources on an in-scope page can still load.</p>
</body>`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

module.exports = { allowProxy, looksLikeDocument, outOfScopeHtml, normalizeHost };
