const { header } = require("./analyze");

const HEADER_NAMES = [
  "Content-Security-Policy",
  "Strict-Transport-Security",
  "X-Frame-Options",
  "X-Content-Type-Options",
  "Referrer-Policy",
  "Permissions-Policy",
  "Cross-Origin-Opener-Policy",
  "Cross-Origin-Resource-Policy",
  "Access-Control-Allow-Origin",
  "Server",
  "X-Powered-By",
];

function cookieFlags(cookie) {
  return {
    name: String(cookie.name || "").slice(0, 80),
    host: String(cookie.host || "").slice(0, 120),
    path: String(cookie.path || "/").slice(0, 80),
    secure: Boolean(cookie.secure),
    httpOnly: Boolean(cookie.httpOnly),
    sameSite: cookie.sameSite ? String(cookie.sameSite).slice(0, 20) : "",
  };
}

function pageInventory(pageUrl, status, headers, cookies) {
  return {
    url: pageUrl,
    status: status || 0,
    https: String(pageUrl).startsWith("https:"),
    at: Date.now(),
    headers: HEADER_NAMES.map((name) => {
      const value = header(headers, name);
      return {
        name,
        present: Boolean(value),
        value: value ? String(value).slice(0, 240) : "",
      };
    }),
    cookies: (cookies || []).map(cookieFlags),
  };
}

function uniqueCookies(pages) {
  const seen = new Map();
  for (const page of pages || []) {
    for (const cookie of page.cookies || []) {
      const key = `${cookie.host}|${cookie.name}|${cookie.path}`;
      seen.set(key, cookie);
    }
  }
  return [...seen.values()];
}

module.exports = { HEADER_NAMES, pageInventory, uniqueCookies, cookieFlags };
