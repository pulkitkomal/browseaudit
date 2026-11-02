function qualityFinding(partial) {
  return {
    source: "heuristic",
    confidence: "high",
    cwe: "",
    category: "quality",
    lane: "quality",
    evidence: "",
    recommendation: "",
    ...partial,
  };
}

function extractMatches(html, regex) {
  const out = [];
  const re = new RegExp(regex.source, regex.flags.includes("g") ? regex.flags : `${regex.flags}g`);
  let match;
  while ((match = re.exec(html))) out.push(match);
  return out;
}

function hasAttr(attrs, name) {
  return new RegExp(`\\b${name}\\s*=`, "i").test(attrs || "");
}

function attrValue(attrs, name) {
  const match = String(attrs || "").match(new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, "i"));
  return match ? match[1] : "";
}

function resourceKind(url, type) {
  const kind = String(type || "").toLowerCase();
  if (kind.startsWith("image/")) return "image";
  if (kind.includes("javascript") || kind.includes("ecmascript")) return "script";
  if (kind.includes("text/css")) return "css";
  if (kind.includes("font/")) return "font";
  const path = String(url || "").split("?")[0].toLowerCase();
  if (/\.(png|jpe?g|gif|webp|svg|ico|avif|bmp)$/.test(path)) return "image";
  if (/\.(js|mjs|cjs)$/.test(path)) return "script";
  if (/\.css$/.test(path)) return "css";
  if (/\.(woff2?|ttf|otf|eot)$/.test(path)) return "font";
  return "";
}

function analyzeQualityHtml(pageUrl, html, status) {
  const findings = [];
  const source = String(html || "");
  if (!status || status >= 400) {
    findings.push(
      qualityFinding({
        id: `page-status:${status || "error"}`,
        severity: !status || status >= 500 ? "high" : "medium",
        title: status ? `Page returned HTTP ${status}` : "Page failed to load",
        description: "This document did not load as a successful page, so users may see an error instead of the content they wanted.",
        evidence: `${pageUrl} → ${status || "error"}`,
        recommendation: "Fix the URL, redirect, or serve a clear recovery page for this status.",
        category: "function",
      })
    );
  }
  if (!source) return findings;

  const htmlTag = source.match(/<html\b([^>]*)>/i);
  if (htmlTag && !hasAttr(htmlTag[1], "lang")) {
    findings.push(
      qualityFinding({
        id: "html-lang-missing",
        severity: "low",
        title: "html lang is missing",
        description: "Assistive technology and browsers do not know what language this page is in.",
        recommendation: "Set lang on the html element, for example lang=\"en\".",
        category: "document",
      })
    );
  }

  const titleMatch = source.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const titleText = titleMatch ? titleMatch[1].replace(/<[^>]+>/g, "").trim() : "";
  if (!titleMatch || !titleText) {
    findings.push(
      qualityFinding({
        id: "title-missing",
        severity: "medium",
        title: "Page title is missing",
        description: "Tabs, bookmarks, and search snippets have nothing useful to show for this page.",
        recommendation: "Add a unique, descriptive <title> for each document.",
        category: "document",
      })
    );
  }

  if (!/<meta\b[^>]*name=["']viewport["']/i.test(source)) {
    findings.push(
      qualityFinding({
        id: "viewport-missing",
        severity: "low",
        title: "Viewport meta tag is missing",
        description: "Phones may zoom this layout as a desktop page.",
        recommendation: "Add <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">.",
        category: "document",
      })
    );
  }

  for (const match of extractMatches(source, /<img\b([^>]*)>/gi).slice(0, 12)) {
    const attrs = match[1] || "";
    if (hasAttr(attrs, "alt")) continue;
    const src = attrValue(attrs, "src") || "(no src)";
    findings.push(
      qualityFinding({
        id: `img-alt-missing:${src}`,
        severity: "low",
        title: "Image is missing alt text",
        description: "Screen readers cannot describe this image, and a failed load has no fallback text.",
        evidence: src.slice(0, 180),
        recommendation: "Add alt that describes the image, or alt=\"\" if it is decorative.",
        category: "controls",
      })
    );
  }

  for (const match of extractMatches(source, /<a\b([^>]*)>/gi).slice(0, 20)) {
    const attrs = match[1] || "";
    const href = attrValue(attrs, "href");
    if (href === "#" || href === "") {
      findings.push(
        qualityFinding({
          id: `hash-link:${attrValue(attrs, "id") || href || "link"}`,
          severity: "low",
          title: "Link does not go anywhere",
          description: "href=\"#\" or an empty href looks clickable but does not take the user to a page.",
          evidence: match[0].slice(0, 160),
          recommendation: "Point the link at a real URL, or use a button if it only runs script.",
          category: "controls",
        })
      );
    }
  }

  const tabLinks = collectTabDocumentLinks(source, pageUrl);
  if (tabLinks.length) {
    findings.push(
      qualityFinding({
        id: "tab-reload:markup",
        severity: "medium",
        title: "Tabs reload the whole page",
        description:
          "These controls look like tabs, but each one is a normal link to another document. Clicking them throws away the current page and loads a new one instead of swapping content in place.",
        evidence: tabLinks
          .slice(0, 6)
          .map((item) => `${item.label} → ${item.href}`)
          .join(" · ")
          .slice(0, 300),
        recommendation:
          "Keep the page shell in place and switch the panel with in-page state or the History API. Use buttons or same-page tabs, not full document navigations.",
        category: "function",
      })
    );
  }

  for (const match of extractMatches(source, /<button\b([^>]*)>([\s\S]*?)<\/button>/gi).slice(0, 12)) {
    const attrs = match[1] || "";
    const text = String(match[2] || "")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim();
    if (text || hasAttr(attrs, "aria-label") || hasAttr(attrs, "aria-labelledby") || hasAttr(attrs, "title")) continue;
    findings.push(
      qualityFinding({
        id: `empty-button:${attrValue(attrs, "id") || attrValue(attrs, "name") || "button"}`,
        severity: "medium",
        title: "Button has no accessible name",
        description: "A control with no text, aria-label, or title cannot be understood by assistive technology or some browsers.",
        evidence: match[0].slice(0, 160),
        recommendation: "Put a visible label in the button, or add aria-label if the design is icon-only.",
        category: "controls",
      })
    );
  }

  return findings;
}

function analyzeQualityDom(pageUrl, quality) {
  const findings = [];
  const data = quality || {};

  for (const err of (data.jsErrors || []).slice(0, 12)) {
    const message = String(err.message || "script error").slice(0, 220);
    findings.push(
      qualityFinding({
        id: `js-error:${message.slice(0, 80)}`,
        severity: "high",
        title: "JavaScript error on the page",
        description: "An uncaught error ran while this page loaded. Features that depend on that script may not work.",
        evidence: [err.source, err.line ? `line ${err.line}` : "", message].filter(Boolean).join(" · ").slice(0, 300),
        recommendation: "Open the browser console on this page, fix the throwing code, and avoid leaving uncaught errors in production.",
        category: "function",
        source: "runtime",
      })
    );
  }

  for (const src of (data.brokenImages || []).slice(0, 10)) {
    findings.push(
      qualityFinding({
        id: `broken-resource:image:${src}`,
        severity: "medium",
        title: "Image failed to load",
        description: "An img element finished loading with no bitmap, so users see a broken image.",
        evidence: String(src).slice(0, 220),
        recommendation: "Fix the image URL or serve a fallback asset.",
        category: "function",
        source: "runtime",
      })
    );
  }

  for (const item of (data.unlabeled || []).slice(0, 12)) {
    const type = String(item.type || item.tag || "control");
    const name = String(item.name || item.id || type);
    const isField = /email|password|text|search|tel|url|textarea|select/i.test(type);
    findings.push(
      qualityFinding({
        id: `unlabeled:${type}:${name}`,
        severity: isField ? "high" : "medium",
        title: isField ? `“${name}” field has no label` : `Control “${name}” has no accessible name`,
        description: isField
          ? "A text field without a label is hard to fill, especially with a password manager or screen reader."
          : "This control has no visible or accessible name, so people cannot tell what it does.",
        evidence: `${type} ${name}`.trim(),
        recommendation: isField
          ? "Associate a <label> with the field, or wrap the field in a label."
          : "Add visible text, aria-label, or a title that names the control.",
        category: "controls",
        source: "runtime",
      })
    );
  }

  for (const item of (data.fullReloads || []).slice(0, 8)) {
    findings.push(fullReloadFinding(pageUrl, item));
  }

  for (const link of (data.hashLinks || []).slice(0, 8)) {
    findings.push(
      qualityFinding({
        id: `hash-link:${link}`,
        severity: "low",
        title: "Link does not go anywhere",
        description: "A link with href=\"#\" or an empty href does not take the user to another page.",
        evidence: String(link).slice(0, 160),
        recommendation: "Point the link at a real URL, or use a button for in-page actions.",
        category: "controls",
        source: "runtime",
      })
    );
  }

  return findings;
}

function qualityFailureFromRequest(request, pageUrl) {
  const status = Number(request.status || 0);
  if (status > 0 && status < 400) return null;
  const kind = resourceKind(request.url, request.type);
  if (!kind) return null;
  const url = String(request.url || "");
  if (/\/probe\.js(\?|$)/i.test(url) || /\/api\//i.test(url)) return null;
  const label = kind === "script" ? "Script" : kind === "css" ? "Stylesheet" : kind === "font" ? "Font" : "Image";
  const severity = kind === "script" || kind === "css" ? "high" : "medium";
  return qualityFinding({
    id: `broken-resource:${kind}:${url}`,
    severity,
    title: `${label} failed to load`,
    description:
      status === 0
        ? `${label} never completed, so part of the page may be missing.`
        : `${label} returned HTTP ${status}, so part of the page may be missing.`,
    evidence: `${url} → ${status || "error"}`,
    recommendation: "Fix the URL, the host, or the response for this asset.",
    category: "function",
    url: pageUrl,
  });
}

function qualityScore(findings, options = {}) {
  const reviewed = Boolean(options.reviewed);
  const list = Array.isArray(findings) ? findings : [];
  if (!reviewed && !list.length) {
    return { label: "—", tone: "", summary: "Open a page to check whether it works." };
  }
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of list) {
    if (counts[item.severity] != null) counts[item.severity] += 1;
  }
  const worst = ["critical", "high", "medium", "low", "info"].find((name) => counts[name] > 0) || null;
  if (worst === "critical" || worst === "high" || worst === "medium") {
    return { label: "Needs work", tone: worst === "medium" ? "medium" : "high", counts, worst };
  }
  if (list.length) return { label: "Pass", tone: "ok", counts, worst };
  return { label: "Pass", tone: "ok", counts, worst: null };
}

function resolveHref(href, pageUrl) {
  try {
    return new URL(String(href || ""), pageUrl).href;
  } catch {
    return String(href || "");
  }
}

function hrefLeavesPage(href, pageUrl) {
  const raw = String(href || "").trim();
  if (!raw || raw === "#" || raw.startsWith("#") || raw.toLowerCase().startsWith("javascript:")) return false;
  try {
    const next = new URL(raw, pageUrl);
    const here = new URL(pageUrl);
    if (next.protocol !== "http:" && next.protocol !== "https:") return false;
    if (next.origin === here.origin && next.pathname === here.pathname && next.search === here.search) return false;
    return true;
  } catch {
    return false;
  }
}

function looksLikeTabAttrs(attrs) {
  const role = attrValue(attrs, "role").toLowerCase();
  const cls = `${attrValue(attrs, "class")} ${attrValue(attrs, "id")}`;
  if (role === "tab") return true;
  if (hasAttr(attrs, "data-tab") || /data-toggle\s*=\s*["']tab["']/i.test(attrs || "")) return true;
  if (/\btabs?\b/i.test(cls)) return true;
  if (hasAttr(attrs, "aria-selected")) return true;
  return false;
}

function collectTabDocumentLinks(html, pageUrl) {
  const links = [];
  const seen = new Set();
  for (const match of extractMatches(html, /<a\b([^>]*)>([\s\S]*?)<\/a>/gi).slice(0, 40)) {
    const attrs = match[1] || "";
    if (!looksLikeTabAttrs(attrs)) continue;
    const href = attrValue(attrs, "href");
    if (!hrefLeavesPage(href, pageUrl)) continue;
    const label = String(match[2] || "")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 80);
    const resolved = resolveHref(href, pageUrl);
    const key = `${label}|${resolved}`;
    if (seen.has(key)) continue;
    seen.add(key);
    links.push({ label: label || resolved, href: resolved });
  }
  return links;
}

function fullReloadFinding(pageUrl, item) {
  const kind = item && item.kind === "app-nav" ? "app-nav" : "tab";
  const label = String((item && (item.label || item.text)) || "control")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 80);
  const from = (item && item.from) || pageUrl || "";
  const to = (item && (item.to || item.href)) || "";
  if (kind === "app-nav") {
    return qualityFinding({
      id: `tab-reload:nav:${label}:${to}`,
      severity: "medium",
      title: `In-app link “${label}” reloaded the whole page`,
      description:
        "This visit already used in-page navigation, but this chrome link caused a full document load. The header and scripts were thrown away and fetched again.",
      evidence: `${from} → ${to}`.slice(0, 300),
      recommendation: "Route in-app links through the same client-side navigation the rest of the site uses, instead of a full page load.",
      category: "function",
      source: "runtime",
    });
  }
  return qualityFinding({
    id: `tab-reload:click:${label}:${to}`,
    severity: "medium",
    title: `Tab “${label}” reloaded the whole page`,
    description:
      "Clicking this tab loaded a new document instead of swapping the panel in place. Users lose in-page state, scroll position, and any work that had not been saved.",
    evidence: `${label}: ${from} → ${to}`.slice(0, 300),
    recommendation:
      "Keep the shell on the page and change the visible panel with in-page state or the History API. Tabs should not be full document navigations.",
    category: "function",
    source: "runtime",
  });
}

const TAB_QUERY = /^(tab|tabs|view|panel|section|mode|selected|screen)$/i;

function changedSearchKeys(fromUrl, toUrl) {
  try {
    const from = new URL(fromUrl);
    const to = new URL(toUrl);
    if (from.origin !== to.origin || from.pathname !== to.pathname) return null;
    const keys = new Set([...from.searchParams.keys(), ...to.searchParams.keys()]);
    const changed = [];
    for (const key of keys) {
      if (from.searchParams.get(key) !== to.searchParams.get(key)) changed.push(key);
    }
    return changed;
  } catch {
    return null;
  }
}

function analyzeQualityNavigation(context = {}) {
  const findings = [];
  const from = context.from || "";
  const to = context.to || "";
  const intent = context.intent;
  if (intent && (intent.kind === "tab" || intent.kind === "app-nav")) {
    if (intent.kind === "app-nav" && !context.clientNav) {
      /* ordinary multi-page nav is fine until the site has already used in-page routing */
    } else {
      findings.push(
        fullReloadFinding(to || from, {
          kind: intent.kind,
          label: intent.label,
          from: intent.from || from,
          to: to || intent.href,
          href: intent.href,
        })
      );
    }
  }
  const changed = from && to ? changedSearchKeys(from, to) : null;
  if (changed && changed.length && changed.every((key) => TAB_QUERY.test(key))) {
    findings.push(
      qualityFinding({
        id: `tab-reload:query:${changed.join(",")}`,
        severity: "medium",
        title: "View switch reloaded the whole page",
        description:
          "The URL only changed a tab/view query parameter, but the browser loaded a new document. That is a full reload for what looks like an in-page switch.",
        evidence: `${from} → ${to}`.slice(0, 300),
        recommendation: "Handle tab and view changes in the page, and update the query string with the History API if it needs to stay bookmarkable.",
        category: "function",
      })
    );
  }
  return findings;
}

module.exports = {
  analyzeQualityHtml,
  analyzeQualityDom,
  analyzeQualityNavigation,
  qualityFailureFromRequest,
  qualityScore,
  resourceKind,
  qualityFinding,
};
