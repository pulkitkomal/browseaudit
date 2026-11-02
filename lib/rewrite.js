const { toProxyPath, directoryUrl, resolveAgainst } = require("./urls");

const URL_ATTRS = [
  "href",
  "src",
  "action",
  "formaction",
  "poster",
  "cite",
  "data-src",
  "data-href",
];

function escapeAttr(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;");
}

function proxify(raw, pageUrl, origin) {
  const abs = resolveAgainst(raw, pageUrl);
  if (!abs) return raw;
  if (abs.startsWith(origin + "/proxy/") || abs.startsWith("/proxy/")) return raw;
  return origin + toProxyPath(abs);
}

function rewriteSrcset(value, pageUrl, origin) {
  return value
    .split(",")
    .map((part) => {
      const trimmed = part.trim();
      if (!trimmed) return part;
      const bits = trimmed.split(/\s+/);
      bits[0] = proxify(bits[0], pageUrl, origin);
      return bits.join(" ");
    })
    .join(", ");
}

function rewriteCss(css, pageUrl, origin) {
  return String(css).replace(
    /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi,
    (full, quote, url) => {
      const next = proxify(url, pageUrl, origin);
      return `url(${quote}${next}${quote})`;
    }
  );
}

function injectHead(html, snippet) {
  if (/<head[^>]*>/i.test(html)) return html.replace(/<head[^>]*>/i, (m) => `${m}${snippet}`);
  if (/<html[^>]*>/i.test(html)) {
    return html.replace(/<html[^>]*>/i, (m) => `${m}<head>${snippet}</head>`);
  }
  return `${snippet}${html}`;
}

function rewriteHtml(html, pageUrl, origin) {
  const base = `<base href="${escapeAttr(origin + toProxyPath(directoryUrl(pageUrl)))}">`;
  const probe = `<script src="${origin}/probe.js" data-origin="${escapeAttr(origin)}" data-page="${escapeAttr(pageUrl)}"></script>`;
  let out = injectHead(html, `${base}${probe}`);

  out = out.replace(
    /\s(href|src|action|formaction|poster|cite|data-src|data-href)\s*=\s*(["'])([^"']*)\2/gi,
    (full, attr, quote, url) => {
      if (URL_ATTRS.includes(attr.toLowerCase()) === false) return full;
      return ` ${attr}=${quote}${proxify(url, pageUrl, origin)}${quote}`;
    }
  );

  out = out.replace(
    /\ssrcset\s*=\s*(["'])([^"']*)\1/gi,
    (full, quote, value) => ` srcset=${quote}${rewriteSrcset(value, pageUrl, origin)}${quote}`
  );

  out = out.replace(
    /<meta\b[^>]*http-equiv=["']refresh["'][^>]*>/gi,
    (tag) =>
      tag.replace(/content=(["'])([^"']*)\1/i, (full, quote, content) => {
        const match = content.match(/^(.*url=)(.+)$/i);
        if (!match) return full;
        return `content=${quote}${match[1]}${proxify(match[2], pageUrl, origin)}${quote}`;
      })
  );

  out = out.replace(
    /\sstyle\s*=\s*(["'])([^"']*)\1/gi,
    (full, quote, css) => ` style=${quote}${rewriteCss(css, pageUrl, origin)}${quote}`
  );

  return out;
}

function rewriteLocation(location, pageUrl, origin) {
  return proxify(location, pageUrl, origin);
}

module.exports = { rewriteHtml, rewriteCss, rewriteLocation, proxify };
