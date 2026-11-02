const { URL } = require("url");

function header(headers, name) {
  const key = Object.keys(headers || {}).find((k) => k.toLowerCase() === name.toLowerCase());
  return key ? headers[key] : "";
}

function headerList(headers, name) {
  const value = header(headers, name);
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function finding(partial) {
  return {
    source: "heuristic",
    confidence: "high",
    cwe: "",
    category: "headers",
    evidence: "",
    recommendation: "",
    ...partial,
  };
}

function analyzeHeaders(pageUrl, status, headers) {
  const findings = [];
  let parsed;
  try {
    parsed = new URL(pageUrl);
  } catch {
    return findings;
  }
  const https = parsed.protocol === "https:";
  const csp = header(headers, "content-security-policy");
  const xfo = header(headers, "x-frame-options");
  const hsts = header(headers, "strict-transport-security");
  const xcto = header(headers, "x-content-type-options");
  const referrer = header(headers, "referrer-policy");
  const coop = header(headers, "cross-origin-opener-policy");
  const acao = header(headers, "access-control-allow-origin");
  const acac = header(headers, "access-control-allow-credentials");
  const server = header(headers, "server");
  const powered = header(headers, "x-powered-by");
  const asp = header(headers, "x-aspnet-version") || header(headers, "x-aspnetmvc-version");

  if (!https) {
    findings.push(
      finding({
        id: "insecure-transport",
        severity: "high",
        category: "transport",
        title: "Page is served over HTTP",
        description:
          "Traffic to this page is not encrypted. Credentials, cookies, and the document can be read or changed on the network.",
        evidence: pageUrl,
        recommendation: "Redirect all HTTP requests to HTTPS and enable HSTS once TLS is working.",
        cwe: "CWE-319",
      })
    );
  }

  if (https && !hsts) {
    findings.push(
      finding({
        id: "hsts-missing",
        severity: "medium",
        category: "headers",
        title: "Strict-Transport-Security is missing",
        description: "Browsers are not told to keep using HTTPS, so users can be downgraded to HTTP on later visits.",
        recommendation: "Send Strict-Transport-Security with a long max-age, includeSubDomains, and preload once you are ready.",
        cwe: "CWE-319",
      })
    );
  }

  if (!csp) {
    findings.push(
      finding({
        id: "csp-missing",
        severity: "medium",
        category: "headers",
        title: "Content-Security-Policy is missing",
        description:
          "Without CSP, a successful XSS bug can load any script. A policy is a strong backup control, not a replacement for encoding.",
        recommendation: "Add a Content-Security-Policy that defaults to none and allowlists only the script and style origins you need.",
        cwe: "CWE-693",
      })
    );
  } else {
    if (/unsafe-inline/.test(csp)) {
      findings.push(
        finding({
          id: "csp-unsafe-inline",
          severity: "medium",
          category: "headers",
          title: "CSP allows unsafe-inline",
          description: "unsafe-inline lets injected script or style run, which removes most of the XSS protection CSP is meant to provide.",
          evidence: csp.slice(0, 240),
          recommendation: "Use nonces or hashes for the scripts you control and drop unsafe-inline.",
          cwe: "CWE-79",
        })
      );
    }
    if (/unsafe-eval/.test(csp)) {
      findings.push(
        finding({
          id: "csp-unsafe-eval",
          severity: "low",
          category: "headers",
          title: "CSP allows unsafe-eval",
          description: "eval-style APIs stay available to injected script.",
          evidence: csp.slice(0, 240),
          recommendation: "Remove unsafe-eval and avoid compiling strings into code.",
          cwe: "CWE-95",
        })
      );
    }
    if (/script-src[^;]*\*/.test(csp) || /default-src[^;]*\*/.test(csp)) {
      findings.push(
        finding({
          id: "csp-wildcard",
          severity: "medium",
          category: "headers",
          title: "CSP script sources include a wildcard",
          description: "A wildcard script source lets the page load script from any host that matches the pattern.",
          evidence: csp.slice(0, 240),
          recommendation: "List the exact hosts that should serve JavaScript.",
          cwe: "CWE-693",
        })
      );
    }
  }

  const frameAncestors = csp && /frame-ancestors/i.test(csp);
  if (!xfo && !frameAncestors) {
    findings.push(
      finding({
        id: "clickjacking",
        severity: "medium",
        category: "headers",
        title: "No clickjacking protection",
        description: "The response has neither X-Frame-Options nor CSP frame-ancestors, so other sites can embed this page.",
        recommendation: "Set Content-Security-Policy: frame-ancestors 'self' (or a trusted list) and keep X-Frame-Options as a legacy fallback.",
        cwe: "CWE-1021",
      })
    );
  }

  if (!xcto || !String(xcto).toLowerCase().includes("nosniff")) {
    findings.push(
      finding({
        id: "nosniff-missing",
        severity: "low",
        category: "headers",
        title: "X-Content-Type-Options is missing",
        description: "Browsers may MIME-sniff this response and treat a non-script as script.",
        recommendation: "Send X-Content-Type-Options: nosniff on every response.",
        cwe: "CWE-16",
      })
    );
  }

  if (!referrer || /unsafe-url/i.test(referrer)) {
    findings.push(
      finding({
        id: "referrer-policy",
        severity: "low",
        category: "headers",
        title: referrer ? "Referrer-Policy is unsafe-url" : "Referrer-Policy is missing",
        description: "The full URL of this page, including query strings, may leak to third-party origins.",
        evidence: referrer || "(none)",
        recommendation: "Send Referrer-Policy: strict-origin-when-cross-origin or stricter.",
        cwe: "CWE-200",
      })
    );
  }

  if (!coop) {
    findings.push(
      finding({
        id: "coop-missing",
        severity: "info",
        category: "headers",
        title: "Cross-Origin-Opener-Policy is missing",
        description: "Without COOP, this window can stay in a browsing context group with cross-origin popups.",
        recommendation: "Consider Cross-Origin-Opener-Policy: same-origin on sensitive pages.",
        cwe: "CWE-346",
      })
    );
  }

  if (acao === "*" && /true/i.test(acac)) {
    findings.push(
      finding({
        id: "cors-wildcard-credentials",
        severity: "high",
        category: "headers",
        title: "CORS allows any origin with credentials",
        description: "Access-Control-Allow-Origin is * while credentials are allowed. Browsers should reject this; it still shows a confused CORS setup.",
        evidence: `ACA-Origin: ${acao}; ACA-Credentials: ${acac}`,
        recommendation: "Reflect a specific allowed origin and only enable credentials when that origin is trusted.",
        cwe: "CWE-942",
      })
    );
  } else if (acao === "*") {
    findings.push(
      finding({
        id: "cors-wildcard",
        severity: "low",
        category: "headers",
        title: "CORS allows any origin",
        description: "Any website can read this response from a browser if the request does not use credentials.",
        evidence: "Access-Control-Allow-Origin: *",
        recommendation: "Allowlist the origins that should read this API instead of using * on private data.",
        cwe: "CWE-942",
      })
    );
  }

  if (server) {
    findings.push(
      finding({
        id: "server-banner",
        severity: "info",
        category: "disclosure",
        title: "Server version is advertised",
        description: "The Server header tells clients which software and version is running.",
        evidence: `Server: ${server}`,
        recommendation: "Omit version numbers from Server and similar headers.",
        cwe: "CWE-200",
      })
    );
  }
  if (powered) {
    findings.push(
      finding({
        id: "powered-by",
        severity: "info",
        category: "disclosure",
        title: "X-Powered-By is advertised",
        evidence: `X-Powered-By: ${powered}`,
        description: "Framework details in this header help an attacker pick known issues for that stack.",
        recommendation: "Disable X-Powered-By in the framework or reverse proxy.",
        cwe: "CWE-200",
      })
    );
  }
  if (asp) {
    findings.push(
      finding({
        id: "aspnet-version",
        severity: "low",
        category: "disclosure",
        title: "ASP.NET version header is present",
        evidence: asp,
        description: "Framework version headers are unused by browsers and useful for fingerprinting.",
        recommendation: "Remove X-AspNet-Version and X-AspNetMvc-Version.",
        cwe: "CWE-200",
      })
    );
  }

  if (status >= 500) {
    findings.push(
      finding({
        id: "server-error",
        severity: "info",
        category: "disclosure",
        title: `Server returned HTTP ${status}`,
        description: "Error responses sometimes include stack traces or framework details.",
        recommendation: "Serve a generic error page and keep diagnostics on the server.",
        cwe: "CWE-209",
      })
    );
  }

  return findings;
}

function analyzeCookies(pageUrl, cookies) {
  const findings = [];
  let https = false;
  try {
    https = new URL(pageUrl).protocol === "https:";
  } catch {
    /* ignore */
  }
  for (const cookie of cookies || []) {
    if (https && !cookie.secure) {
      findings.push(
        finding({
          id: `cookie-secure:${cookie.name}`,
          severity: "high",
          category: "cookies",
          title: `Cookie “${cookie.name}” is missing Secure`,
          description: "The cookie can be sent on HTTP requests, so a downgrade or mixed request can leak it.",
          evidence: cookie.name,
          recommendation: "Set the Secure flag on every cookie used on an HTTPS site.",
          cwe: "CWE-614",
        })
      );
    }
    if (!cookie.httpOnly) {
      findings.push(
        finding({
          id: `cookie-httponly:${cookie.name}`,
          severity: "medium",
          category: "cookies",
          title: `Cookie “${cookie.name}” is missing HttpOnly`,
          description: "Page script can read this cookie if XSS occurs.",
          evidence: cookie.name,
          recommendation: "Set HttpOnly on session and auth cookies that JavaScript does not need to read.",
          cwe: "CWE-1004",
        })
      );
    }
    if (!cookie.sameSite || /^none$/i.test(cookie.sameSite)) {
      findings.push(
        finding({
          id: `cookie-samesite:${cookie.name}`,
          severity: /^none$/i.test(cookie.sameSite) ? "medium" : "low",
          category: "cookies",
          title: `Cookie “${cookie.name}” has a weak SameSite policy`,
          description: cookie.sameSite
            ? "SameSite=None sends this cookie on cross-site requests."
            : "Without SameSite, browsers may still send this cookie on some cross-site requests.",
          evidence: `${cookie.name}; SameSite=${cookie.sameSite || "(unset)"}`,
          recommendation: "Use SameSite=Lax or Strict unless the cookie must be sent on cross-site requests, in which case it also needs Secure.",
          cwe: "CWE-1275",
        })
      );
    }
  }
  return findings;
}

function extractMatches(html, regex) {
  const out = [];
  const re = new RegExp(regex.source, regex.flags.includes("g") ? regex.flags : regex.flags + "g");
  let match;
  while ((match = re.exec(html))) out.push(match);
  return out;
}

function analyzeHtml(pageUrl, html) {
  const findings = [];
  if (!html) return findings;
  let parsed;
  try {
    parsed = new URL(pageUrl);
  } catch {
    return findings;
  }
  const https = parsed.protocol === "https:";

  for (const comment of extractMatches(html, /<!--([\s\S]*?)-->/g)) {
    const body = comment[1];
    const secret = body.match(
      /(api[_-]?key|secret|password|passwd|token|bearer|sk_live|AKIA[0-9A-Z]{8,})[^\n<]{0,60}/i
    );
    if (secret) {
      findings.push(
        finding({
          id: "html-comment-secret",
          severity: "high",
          category: "disclosure",
          title: "Possible secret in an HTML comment",
          description: "Comments are visible in View Source and are a common place to leave leftover credentials.",
          evidence: secret[0].replace(/[A-Za-z0-9_\-]{8,}/g, (m) => `${m.slice(0, 3)}…`),
          recommendation: "Remove secrets from templates and rotate anything that was committed or shipped.",
          cwe: "CWE-615",
        })
      );
    }
  }

  const forms = extractMatches(
    html,
    /<form\b([^>]*)>([\s\S]*?)<\/form>/gi
  );
  for (const form of forms) {
    const attrs = form[1] || "";
    const body = form[2] || "";
    const action = (attrs.match(/\baction=["']([^"']*)["']/i) || [, ""])[1];
    const method = ((attrs.match(/\bmethod=["']([^"']*)["']/i) || [, "get"])[1] || "get").toLowerCase();
    const hasPassword = /<input\b[^>]*type=["']password["']/i.test(body);
    const hasToken = /<input\b[^>]*(name|id)=["'][^"']*(csrf|token|nonce|authenticity)[^"']*["']/i.test(
      body
    );
    let actionUrl = action;
    try {
      actionUrl = action ? new URL(action, pageUrl).href : pageUrl;
    } catch {
      /* keep raw */
    }
    if (hasPassword && (actionUrl || "").startsWith("http:")) {
      findings.push(
        finding({
          id: "password-over-http",
          severity: "critical",
          category: "forms",
          title: "Password form submits over HTTP",
          description: "The login form can send the password in cleartext.",
          evidence: actionUrl,
          recommendation: "Serve the form and its action URL on HTTPS only.",
          cwe: "CWE-319",
        })
      );
    }
    if (hasPassword && method === "get") {
      findings.push(
        finding({
          id: "password-get",
          severity: "high",
          category: "forms",
          title: "Password form uses GET",
          description: "Passwords in query strings end up in logs, history, and Referer headers.",
          recommendation: "Submit credentials with POST over HTTPS.",
          cwe: "CWE-598",
        })
      );
    }
    if (method === "post" && !hasToken) {
      findings.push(
        finding({
          id: `csrf-token-missing:${actionUrl || pageUrl}`,
          severity: hasPassword ? "high" : "medium",
          category: "forms",
          title: hasPassword ? "Login form has no CSRF token" : "POST form has no CSRF token",
          description:
            "No hidden field whose name looks like a CSRF token was found. Cross-site posts may be accepted if the server does not check another signal.",
          evidence: `method=POST action=${actionUrl || "(same page)"}`,
          recommendation: "Add an anti-CSRF token bound to the session and verify it on the server, or use SameSite=Strict cookies plus additional checks.",
          cwe: "CWE-352",
          confidence: "medium",
        })
      );
    }
    if (hasPassword && /autocomplete=["']on["']/i.test(body)) {
      findings.push(
        finding({
          id: "password-autocomplete",
          severity: "low",
          category: "forms",
          title: "Password field allows autocomplete",
          description: "The password field explicitly opts into browser autocomplete.",
          recommendation: "Use autocomplete=\"current-password\" or \"new-password\" on purpose; avoid autocomplete=on on sensitive fields.",
          cwe: "CWE-522",
        })
      );
    }
  }

  if (https) {
    for (const match of extractMatches(
      html,
      /\s(?:src|href|action|poster)=["'](http:\/\/[^"']+)["']/gi
    )) {
      const url = match[1];
      const active = /\ssrc=["']http:/i.test(match[0]) || /\saction=["']http:/i.test(match[0]);
      findings.push(
        finding({
          id: `mixed-content:${url}`,
          severity: active ? "high" : "medium",
          category: "transport",
          title: active ? "Active mixed content" : "Mixed content resource",
          description: active
            ? "An HTTP script or form target is loaded from an HTTPS page, which browsers block or treat as a serious downgrade."
            : "An HTTP subresource is referenced from an HTTPS page.",
          evidence: url,
          recommendation: "Load every subresource over HTTPS, or use protocol-relative / HTTPS-only URLs.",
          cwe: "CWE-311",
        })
      );
    }
  }

  for (const match of extractMatches(html, /<a\b[^>]*href=["']javascript:[^"']+["'][^>]*>/gi)) {
    findings.push(
      finding({
        id: "javascript-url",
        severity: "medium",
        category: "dom",
        title: "javascript: URL in a link",
        description: "javascript: links run script in the page origin when clicked.",
        evidence: match[0].slice(0, 160),
        recommendation: "Use a button and an event listener instead of javascript: URLs.",
        cwe: "CWE-79",
      })
    );
  }

  const inlineHandlers = extractMatches(html, /\son\w+\s*=\s*["'][^"']+["']/gi);
  if (inlineHandlers.length) {
    findings.push(
      finding({
        id: "inline-handlers",
        severity: "medium",
        category: "dom",
        title: `${inlineHandlers.length} inline event handler${inlineHandlers.length === 1 ? "" : "s"}`,
        description:
          "Inline on* handlers are XSS sinks and are blocked by a strict CSP. They often mean user-controlled strings can be concatenated into HTML.",
        evidence: inlineHandlers
          .slice(0, 3)
          .map((m) => m[0].slice(0, 80))
          .join(" · "),
        recommendation: "Move listeners into external script and encode untrusted HTML.",
        cwe: "CWE-79",
      })
    );
  }

  for (const match of extractMatches(
    html,
    /<a\b[^>]*target=["']_blank["'][^>]*>/gi
  )) {
    if (!/\brel=["'][^"']*(noopener|noreferrer)[^"']*["']/i.test(match[0])) {
      findings.push(
        finding({
          id: "tabnabbing",
          severity: "low",
          category: "dom",
          title: "target=_blank without rel=noopener",
          description: "The opened page can retain a handle to this window via window.opener.",
          evidence: match[0].slice(0, 160),
          recommendation: "Add rel=\"noopener noreferrer\" to external target=_blank links.",
          cwe: "CWE-1022",
        })
      );
    }
  }

  for (const match of extractMatches(html, /<script\b([^>]*)>/gi)) {
    const attrs = match[1] || "";
    const src = (attrs.match(/\bsrc=["']([^"']+)["']/i) || [])[1];
    if (!src) continue;
    let thirdParty = false;
    try {
      const scriptUrl = new URL(src, pageUrl);
      thirdParty = scriptUrl.host !== parsed.host;
    } catch {
      thirdParty = true;
    }
    if (thirdParty && !/\bintegrity=["']/.test(attrs)) {
      findings.push(
        finding({
          id: `sri-missing:${src}`,
          severity: "medium",
          category: "third-party",
          title: "Third-party script without Subresource Integrity",
          description: "If the CDN is compromised, this page will run whatever script is served.",
          evidence: src,
          recommendation: "Add an integrity hash and crossorigin=\"anonymous\" on third-party scripts, or self-host them.",
          cwe: "CWE-345",
        })
      );
    }
  }

  if (/document\.write\s*\(|\.innerHTML\s*=|\beval\s*\(/i.test(html)) {
    findings.push(
      finding({
        id: "dangerous-sinks",
        severity: "medium",
        category: "dom",
        title: "Page source includes document.write, innerHTML, or eval",
        description:
          "These APIs are common DOM XSS sinks when they receive untrusted data. This is a static match in the HTML/inline script, not proof of a working bug.",
        recommendation: "Prefer textContent or safe templating, and keep untrusted data out of these APIs.",
        cwe: "CWE-79",
        confidence: "medium",
      })
    );
  }

  return findings;
}

function analyzeDom(pageUrl, dom) {
  const findings = [];
  if (!dom) return findings;
  if (dom.jsCookies && dom.jsCookies.length) {
    findings.push(
      finding({
        id: "document-cookie",
        severity: "medium",
        category: "cookies",
        title: "Cookies readable from JavaScript",
        description: "document.cookie returned names, so those cookies are not HttpOnly.",
        evidence: dom.jsCookies.join(", "),
        recommendation: "Set HttpOnly on session cookies that script does not need.",
        cwe: "CWE-1004",
        source: "runtime",
      })
    );
  }
  if (dom.storageKeys && dom.storageKeys.length) {
    findings.push(
      finding({
        id: "web-storage-tokens",
        severity: "medium",
        category: "dom",
        title: "Web storage keys look like auth material",
        description:
          "Tokens in localStorage or sessionStorage survive XSS and are not bound to HttpOnly cookies.",
        evidence: dom.storageKeys.join(", "),
        recommendation: "Prefer HttpOnly, Secure, SameSite cookies for session material.",
        cwe: "CWE-922",
        source: "runtime",
        confidence: "medium",
      })
    );
  }
  if (dom.passwordOnHttp) {
    findings.push(
      finding({
        id: "runtime-password-http",
        severity: "critical",
        category: "forms",
        title: "Password field present on an HTTP page",
        description: "A password input was found after the page ran, still on HTTP.",
        recommendation: "Serve authentication flows on HTTPS only.",
        cwe: "CWE-319",
        source: "runtime",
      })
    );
  }
  return findings;
}

function buildSnapshot(pageUrl, status, headers, cookies, html, extraDom) {
  const csp = header(headers, "content-security-policy");
  const excerpt = String(html || "")
    .replace(/<script\b[\s\S]*?<\/script>/gi, "<script>/* omitted */</script>")
    .replace(/<style\b[\s\S]*?<\/style>/gi, "<style>/* omitted */</style>")
    .slice(0, 9000);
  const forms = extractMatches(html || "", /<form\b([^>]*)>([\s\S]*?)<\/form>/gi).map((form) => {
    const attrs = form[1] || "";
    const body = form[2] || "";
    const fields = extractMatches(body, /<input\b([^>]*)>/gi).map((input) => {
      const a = input[1] || "";
      return {
        type: ((a.match(/\btype=["']([^"']*)["']/i) || [])[1] || "text").toLowerCase(),
        name: (a.match(/\bname=["']([^"']*)["']/i) || [])[1] || "",
        autocomplete: (a.match(/\bautocomplete=["']([^"']*)["']/i) || [])[1] || "",
      };
    });
    return {
      method: ((attrs.match(/\bmethod=["']([^"']*)["']/i) || [, "GET"])[1] || "GET").toUpperCase(),
      action: (attrs.match(/\baction=["']([^"']*)["']/i) || [])[1] || "",
      fields,
    };
  });
  const scripts = extractMatches(html || "", /<script\b([^>]*)>/gi).map((m) => {
    const attrs = m[1] || "";
    return {
      src: (attrs.match(/\bsrc=["']([^"']+)["']/i) || [])[1] || null,
      integrity: /\bintegrity=/.test(attrs),
      inline: !/\bsrc=/.test(attrs),
    };
  });
  return {
    url: pageUrl,
    status,
    headers: {
      "content-security-policy": csp || null,
      "strict-transport-security": header(headers, "strict-transport-security") || null,
      "x-frame-options": header(headers, "x-frame-options") || null,
      "x-content-type-options": header(headers, "x-content-type-options") || null,
      "referrer-policy": header(headers, "referrer-policy") || null,
      "access-control-allow-origin": header(headers, "access-control-allow-origin") || null,
      "set-cookie-names": (cookies || []).map((c) => ({
        name: c.name,
        secure: !!c.secure,
        httpOnly: !!c.httpOnly,
        sameSite: c.sameSite || null,
      })),
      server: header(headers, "server") || null,
      "x-powered-by": header(headers, "x-powered-by") || null,
    },
    forms,
    scripts: scripts.slice(0, 40),
    comments: extractMatches(html || "", /<!--([\s\S]*?)-->/g)
      .map((m) => m[1].trim().slice(0, 200))
      .filter(Boolean)
      .slice(0, 8),
    htmlExcerpt: excerpt,
    runtime: extraDom || null,
  };
}

function analyzePage(pageUrl, status, headers, cookies, html) {
  return [
    ...analyzeHeaders(pageUrl, status, headers),
    ...analyzeCookies(pageUrl, cookies),
    ...analyzeHtml(pageUrl, html),
  ];
}

module.exports = {
  analyzePage,
  analyzeDom,
  analyzeHeaders,
  buildSnapshot,
  header,
};
