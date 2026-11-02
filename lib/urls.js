const { URL } = require("url");

const PROXY_PREFIX = "/proxy/";

function toProxyPath(target) {
  const u = new URL(target);
  const path = `${u.pathname}${u.search}` || "/";
  return `${PROXY_PREFIX}${u.protocol.replace(":", "")}/${u.host}${path}`;
}

function fromProxyPath(reqUrl) {
  if (!reqUrl.startsWith(PROXY_PREFIX)) return null;
  const rest = reqUrl.slice(PROXY_PREFIX.length);
  const schemeEnd = rest.indexOf("/");
  if (schemeEnd <= 0) return null;
  const scheme = rest.slice(0, schemeEnd);
  if (scheme !== "http" && scheme !== "https") return null;
  const after = rest.slice(schemeEnd + 1);
  if (!after) return null;
  const split = after.search(/[/?#]/);
  const host = split === -1 ? after : after.slice(0, split);
  if (!host) return null;
  let path = split === -1 ? "/" : after.slice(split);
  if (path.startsWith("?")) path = `/${path}`;
  if (!path.startsWith("/")) path = `/${path}`;
  try {
    return new URL(`${scheme}://${host}${path}`).href;
  } catch {
    return null;
  }
}

function directoryUrl(pageUrl) {
  const u = new URL(pageUrl);
  if (u.pathname.endsWith("/")) return u.href;
  u.pathname = u.pathname.slice(0, u.pathname.lastIndexOf("/") + 1) || "/";
  u.hash = "";
  return u.href;
}

function resolveAgainst(raw, pageUrl) {
  const value = String(raw || "").trim();
  if (!value) return null;
  const lower = value.toLowerCase();
  if (
    lower.startsWith("#") ||
    lower.startsWith("javascript:") ||
    lower.startsWith("mailto:") ||
    lower.startsWith("tel:") ||
    lower.startsWith("data:") ||
    lower.startsWith("blob:") ||
    lower.startsWith("about:")
  ) {
    return null;
  }
  try {
    return new URL(value, pageUrl).href;
  } catch {
    return null;
  }
}

function hostOf(targetUrl) {
  try {
    return new URL(targetUrl).host.toLowerCase();
  } catch {
    return "";
  }
}

function normalizeHost(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(raw)) return new URL(raw).host.toLowerCase();
    return new URL(`https://${raw}`).host.toLowerCase();
  } catch {
    return raw.toLowerCase();
  }
}

function requestHosts(req) {
  const hosts = new Set();
  const add = (value) => {
    const host = String(value || "")
      .split(",")[0]
      .trim()
      .toLowerCase();
    if (host) hosts.add(host);
    const name = host.split(":")[0];
    if (name) hosts.add(name);
  };
  if (req && req.headers) {
    add(req.headers.host);
    add(req.headers["x-forwarded-host"]);
  }
  hosts.add("127.0.0.1");
  hosts.add("localhost");
  hosts.add("::1");
  return hosts;
}

function isLabTarget(targetUrl, req) {
  let u;
  try {
    u = new URL(targetUrl);
  } catch {
    return false;
  }
  if (!u.pathname.startsWith("/lab")) return false;
  const host = u.host.toLowerCase();
  const hostname = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return requestHosts(req).has(host) || requestHosts(req).has(hostname);
}

function normalizePageUrl(url) {
  try {
    const u = new URL(url);
    u.hash = "";
    return u.href;
  } catch {
    return String(url || "");
  }
}

function samePage(a, b) {
  const na = normalizePageUrl(a);
  const nb = normalizePageUrl(b);
  if (!na || !nb) return false;
  if (na === nb) return true;
  try {
    const strip = (value) => {
      const u = new URL(value);
      let path = u.pathname || "/";
      if (path.endsWith("/index.html")) path = path.slice(0, -10) || "/";
      if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
      return `${u.protocol}//${u.host}${path}${u.search}`;
    };
    return strip(na) === strip(nb);
  } catch {
    return false;
  }
}

function isBlockedTarget(targetUrl) {
  let u;
  try {
    u = new URL(targetUrl);
  } catch {
    return "The URL could not be parsed.";
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return "Only http and https URLs can be opened.";
  }
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "169.254.169.254" || host === "metadata.google.internal") {
    return "That host is blocked.";
  }
  return null;
}

function publicOrigin(req) {
  const proto = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers.host || `127.0.0.1:${process.env.PORT || 8790}`;
  return `${proto}://${host}`;
}

module.exports = {
  PROXY_PREFIX,
  toProxyPath,
  fromProxyPath,
  directoryUrl,
  resolveAgainst,
  isBlockedTarget,
  publicOrigin,
  hostOf,
  normalizeHost,
  isLabTarget,
  samePage,
  normalizePageUrl,
};
