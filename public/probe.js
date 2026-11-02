(function () {
  const script = document.currentScript;
  const origin = script && script.dataset.origin;
  const page = script && script.dataset.page;
  if (!origin || !page) return;

  const jsErrors = [];
  const brokenImages = [];

  function originalUrl(href) {
    try {
      const u = new URL(href, location.href);
      if (!u.pathname.startsWith("/proxy/")) return u.href;
      const rest = u.pathname.slice("/proxy/".length) + u.search;
      const schemeEnd = rest.indexOf("/");
      if (schemeEnd <= 0) return u.href;
      return `${rest.slice(0, schemeEnd)}://${rest.slice(schemeEnd + 1)}`;
    } catch {
      return href;
    }
  }

  function proxify(raw) {
    try {
      const abs = new URL(raw, page);
      if (abs.protocol !== "http:" && abs.protocol !== "https:") return raw;
      if (abs.href.startsWith(origin + "/proxy/")) return raw;
      if (abs.origin === origin) return abs.href;
      return origin + "/proxy/" + abs.protocol.replace(":", "") + "/" + abs.host + (abs.pathname || "/") + abs.search;
    } catch {
      return raw;
    }
  }

  window.addEventListener(
    "error",
    (event) => {
      const target = event.target;
      if (target && target !== window) {
        if (target.tagName === "IMG") {
          const src = originalUrl(target.currentSrc || target.src || "");
          if (src && brokenImages.length < 12) brokenImages.push(src);
        }
        return;
      }
      if (jsErrors.length >= 12) return;
      jsErrors.push({
        message: String(event.message || "script error").slice(0, 220),
        source: originalUrl(event.filename || ""),
        line: event.lineno || 0,
      });
    },
    true
  );

  window.addEventListener("unhandledrejection", (event) => {
    if (jsErrors.length >= 12) return;
    const reason = event.reason;
    const message = reason && reason.message ? reason.message : String(reason || "unhandledrejection");
    jsErrors.push({ message: String(message).slice(0, 220), source: "", line: 0 });
  });

  const rawFetch = window.fetch;
  window.fetch = function (input, init) {
    try {
      if (typeof input === "string") input = proxify(input);
      else if (input instanceof Request) input = new Request(proxify(input.url), input);
    } catch {
      /* keep original */
    }
    return rawFetch.call(this, input, init);
  };

  const rawOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    return rawOpen.call(this, method, typeof url === "string" ? proxify(url) : url, ...rest);
  };

  function notify(type, extra) {
    try {
      window.parent.postMessage({ type, url: page, href: originalUrl(location.href), ...extra }, origin);
    } catch {
      /* ignore */
    }
  }

  function storageKeys() {
    const keys = [];
    try {
      for (let i = 0; i < localStorage.length; i += 1) {
        const key = localStorage.key(i) || "";
        if (/token|session|auth|jwt|secret|api/i.test(key)) keys.push("localStorage:" + key);
      }
      for (let i = 0; i < sessionStorage.length; i += 1) {
        const key = sessionStorage.key(i) || "";
        if (/token|session|auth|jwt|secret|api/i.test(key)) keys.push("sessionStorage:" + key);
      }
    } catch {
      /* ignore */
    }
    return keys;
  }

  function collectDom() {
    const jsCookies = [];
    try {
      for (const part of document.cookie.split(";")) {
        const name = part.split("=")[0].trim();
        if (name) jsCookies.push(name);
      }
    } catch {
      /* ignore */
    }
    return {
      jsCookies,
      storageKeys: storageKeys(),
      passwordOnHttp: originalUrl(location.href).startsWith("http:") && !!document.querySelector('input[type="password"]'),
      forms: document.forms.length,
      scripts: document.scripts.length,
    };
  }

  function accessibleName(el) {
    if (el.getAttribute("aria-label") || el.getAttribute("aria-labelledby") || el.getAttribute("title")) return true;
    if (el.labels && el.labels.length) return true;
    if (el.id) {
      try {
        const esc = window.CSS && CSS.escape ? CSS.escape(el.id) : el.id.replace(/"/g, "");
        if (document.querySelector(`label[for="${esc}"]`)) return true;
      } catch {
        /* ignore */
      }
    }
    const text = String(el.textContent || "").replace(/\s+/g, " ").trim();
    if (text) return true;
    if ((el.tagName === "INPUT" || el.tagName === "BUTTON") && String(el.value || "").trim()) return true;
    return false;
  }

  function collectQuality() {
    const unlabeled = [];
    const hashLinks = [];
    const images = brokenImages.slice();
    const nodes = document.querySelectorAll("input, textarea, select, button");
    for (const el of nodes) {
      if (unlabeled.length >= 12) break;
      const type = String(el.type || el.tagName.toLowerCase()).toLowerCase();
      if (el.disabled || type === "hidden") continue;
      if (accessibleName(el)) continue;
      unlabeled.push({ tag: el.tagName.toLowerCase(), type, name: el.name || el.id || "", id: el.id || "" });
    }
    for (const a of document.querySelectorAll("a[href]")) {
      if (hashLinks.length >= 8) break;
      const href = a.getAttribute("href");
      if (href === "#" || href === "") {
        hashLinks.push(String(a.textContent || href).replace(/\s+/g, " ").trim().slice(0, 80) || href);
      }
    }
    for (const img of document.images) {
      if (images.length >= 10) break;
      if (img.complete && (!img.naturalWidth || !img.naturalHeight) && (img.currentSrc || img.src)) {
        images.push(originalUrl(img.currentSrc || img.src));
      }
    }
    return {
      jsErrors: jsErrors.slice(0, 12),
      unlabeled,
      hashLinks,
      brokenImages: [...new Set(images)].slice(0, 10),
      tabLinks: collectTabLinks(),
    };
  }

  function classTrail(el) {
    let text = "";
    let node = el;
    for (let i = 0; i < 4 && node && node !== document.body; i += 1) {
      text += " " + (node.className || "") + " " + (node.id || "");
      node = node.parentElement;
    }
    return text;
  }

  function sameOriginHref(href) {
    try {
      const next = new URL(href, page);
      const here = new URL(page);
      return next.origin === here.origin;
    } catch {
      return false;
    }
  }

  function leavesPage(href) {
    const raw = String(href || "").trim();
    if (!raw || raw === "#" || raw.startsWith("#") || raw.toLowerCase().startsWith("javascript:")) return false;
    try {
      const next = new URL(raw, page);
      const here = new URL(page);
      if (next.protocol !== "http:" && next.protocol !== "https:") return false;
      return !(next.origin === here.origin && next.pathname === here.pathname && next.search === here.search);
    } catch {
      return false;
    }
  }

  function collectTabLinks() {
    const nodes = document.querySelectorAll(
      '[role="tab"][href], [role="tablist"] a[href], [data-tab][href], a[data-toggle="tab"], a[data-bs-toggle="tab"], a[aria-selected], .tabs a[href], [class~="tab"] a[href], [class~="tabs"] a[href]'
    );
    const out = [];
    const seen = new Set();
    for (const el of nodes) {
      if (out.length >= 10) break;
      const href = originalUrl(el.href || el.getAttribute("href") || "");
      if (!leavesPage(el.getAttribute("href") || el.href || "")) continue;
      const label = String(el.getAttribute("aria-label") || el.textContent || "")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 80);
      const key = label + "|" + href;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ label: label || href, href });
    }
    return out;
  }

  function classifyClick(start) {
    if (!start || start.nodeType !== 1) return null;
    const tab = start.closest(
      '[role="tab"], [role="tablist"] a, [role="tablist"] button, [data-tab], [data-toggle="tab"], [data-bs-toggle="tab"]'
    );
    const selected = !tab ? start.closest("[aria-selected]") : null;
    const node = tab || (selected && selected.closest("nav, [role='navigation'], [class*='tab']") ? selected : null);
    const trail = classTrail(start);
    const classTab = !node && /\btabs?\b/i.test(trail) ? start.closest("a, button") : null;
    const target = node || classTab;
    if (target) {
      const link = target.closest("a[href]") || target;
      const hrefAttr = link.getAttribute && link.getAttribute("href");
      if (hrefAttr && !leavesPage(hrefAttr) && hrefAttr !== "#" && !hrefAttr.startsWith("#")) return null;
      if (link.target && link.target !== "_self") return null;
      return {
        kind: "tab",
        label: String(target.getAttribute("aria-label") || target.textContent || "")
          .replace(/\s+/g, " ")
          .trim()
          .slice(0, 80),
        href: originalUrl(link.href || hrefAttr || location.href),
        from: page,
      };
    }
    const nav = start.closest("nav a[href], header a[href], [role='navigation'] a[href]");
    if (!nav || nav.target && nav.target !== "_self") return null;
    const href = nav.getAttribute("href") || "";
    if (!sameOriginHref(href) || !leavesPage(href)) return null;
    return {
      kind: "app-nav",
      label: String(nav.getAttribute("aria-label") || nav.textContent || "")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 80),
      href: originalUrl(nav.href || href),
      from: page,
    };
  }

  let pendingIntent = null;

  function postQuality(payload) {
    const body = JSON.stringify({ url: page, ...payload });
    try {
      if (navigator.sendBeacon) {
        navigator.sendBeacon(origin + "/api/quality", new Blob([body], { type: "application/json" }));
        return;
      }
    } catch {
      /* fall through */
    }
    try {
      rawFetch.call(window, origin + "/api/quality", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
        keepalive: true,
      });
    } catch {
      /* ignore */
    }
  }

  document.addEventListener(
    "click",
    (event) => {
      const intent = classifyClick(event.target);
      if (!intent) return;
      pendingIntent = { ...intent, at: Date.now() };
      notify("browseaudit:intent", { intent });
      postQuality({ intent });
    },
    true
  );

  function reportDom() {
    const dom = collectDom();
    const quality = collectQuality();
    notify("browseaudit:dom", { dom, quality });
    try {
      rawFetch.call(window, origin + "/api/dom", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: page, dom, quality }),
      });
    } catch {
      /* ignore */
    }
  }

  const push = history.pushState;
  history.pushState = function () {
    const result = push.apply(this, arguments);
    pendingIntent = null;
    notify("browseaudit:nav");
    notify("browseaudit:client-nav");
    postQuality({ clientNav: true });
    return result;
  };
  const replace = history.replaceState;
  history.replaceState = function () {
    const result = replace.apply(this, arguments);
    pendingIntent = null;
    notify("browseaudit:client-nav");
    postQuality({ clientNav: true });
    return result;
  };
  window.addEventListener("popstate", () => notify("browseaudit:nav"));
  notify("browseaudit:nav");
  if (document.readyState === "complete") reportDom();
  else window.addEventListener("load", reportDom);
})();
