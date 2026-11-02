function splitSetCookie(value) {
  if (Array.isArray(value)) return value;
  if (!value) return [];
  return String(value).split(/,(?=\s*[^;=,]+=)/);
}

function parseSetCookie(raw, pageUrl) {
  const chunks = String(raw)
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean);
  if (!chunks.length) return null;
  const eq = chunks[0].indexOf("=");
  if (eq <= 0) return null;
  const cookie = {
    name: chunks[0].slice(0, eq).trim(),
    value: chunks[0].slice(eq + 1),
    httpOnly: false,
    secure: false,
    sameSite: null,
    path: "/",
    domain: null,
    expires: null,
  };
  for (const attr of chunks.slice(1)) {
    const [key, ...rest] = attr.split("=");
    const name = key.trim().toLowerCase();
    const val = rest.join("=").trim();
    if (name === "httponly") cookie.httpOnly = true;
    else if (name === "secure") cookie.secure = true;
    else if (name === "samesite") cookie.sameSite = val || "true";
    else if (name === "path") cookie.path = val || "/";
    else if (name === "domain") cookie.domain = val;
    else if (name === "expires") cookie.expires = val;
  }
  try {
    cookie.host = new URL(pageUrl).hostname;
  } catch {
    cookie.host = "";
  }
  return cookie;
}

function cookieHeaderFor(jar, targetUrl) {
  let host;
  let path;
  try {
    const u = new URL(targetUrl);
    host = u.hostname;
    path = u.pathname || "/";
  } catch {
    return "";
  }
  const parts = [];
  for (const cookie of jar.values()) {
    const domain = (cookie.domain || cookie.host || "").replace(/^\./, "");
    if (domain && host !== domain && !host.endsWith(`.${domain}`)) continue;
    const cpath = cookie.path || "/";
    if (!path.startsWith(cpath)) continue;
    parts.push(`${cookie.name}=${cookie.value}`);
  }
  return parts.join("; ");
}

class CookieJar {
  constructor() {
    this.jar = new Map();
  }

  remember(setCookieHeaders, pageUrl) {
    const stored = [];
    for (const raw of splitSetCookie(setCookieHeaders)) {
      const cookie = parseSetCookie(raw, pageUrl);
      if (!cookie) continue;
      this.jar.set(`${cookie.host}|${cookie.name}`, cookie);
      stored.push(cookie);
    }
    return stored;
  }

  header(targetUrl) {
    return cookieHeaderFor(this.jar, targetUrl);
  }

  clear() {
    this.jar.clear();
  }
}

module.exports = { CookieJar, parseSetCookie, splitSetCookie };
