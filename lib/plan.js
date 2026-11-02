const { gradeFromFindings } = require("./grade");
const { qualityScore } = require("./quality");

const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings || []) {
    if (counts[finding.severity] != null) counts[finding.severity] += 1;
  }
  return counts;
}

const QUALITY_GROUPS = new Set([
  "broken-resource",
  "js-error",
  "unlabeled",
  "empty-button",
  "img-alt-missing",
  "hash-link",
  "viewport-missing",
  "html-lang-missing",
  "title-missing",
  "page-status",
  "tab-reload",
]);

function groupKey(finding) {
  const id = String(finding.id || finding.title || "");
  const prefix = id.split(":")[0];
  if (
    prefix.startsWith("cookie-") ||
    prefix === "sri-missing" ||
    prefix === "mixed-content" ||
    prefix === "csrf-token-missing" ||
    prefix === "tabnabbing" ||
    prefix === "javascript-url" ||
    QUALITY_GROUPS.has(prefix)
  ) {
    return prefix;
  }
  return id || finding.title;
}

function groupedTitle(key, items) {
  const names = items
    .map((item) => String(item.id || "").split(":").slice(1).join(":"))
    .filter(Boolean);
  if (key === "cookie-secure") return `Set the Secure flag on cookies${names.length ? ` (${names.join(", ")})` : ""}`;
  if (key === "cookie-httponly") return `Set HttpOnly on cookies${names.length ? ` (${names.join(", ")})` : ""}`;
  if (key === "cookie-samesite") return `Tighten SameSite on cookies${names.length ? ` (${names.join(", ")})` : ""}`;
  if (key === "sri-missing") return "Add Subresource Integrity to third-party scripts";
  if (key === "mixed-content") return "Serve every subresource over HTTPS";
  if (key === "csrf-token-missing") return "Add CSRF tokens to POST forms";
  if (key === "tabnabbing") return "Add rel=noopener to target=_blank links";
  if (key === "javascript-url") return "Replace javascript: URLs with proper handlers";
  if (key === "broken-resource") return "Fix scripts, styles, fonts, or images that failed to load";
  if (key === "js-error") return "Stop uncaught JavaScript errors";
  if (key === "unlabeled") return "Label form fields and controls";
  if (key === "empty-button") return "Give buttons an accessible name";
  if (key === "img-alt-missing") return "Add alt text to images";
  if (key === "hash-link") return "Replace placeholder links with real destinations";
  if (key === "viewport-missing") return "Add a viewport meta tag";
  if (key === "html-lang-missing") return "Set lang on the html element";
  if (key === "title-missing") return "Add a page title";
  if (key === "page-status") return "Fix pages that return an error status";
  if (key === "tab-reload") return "Keep tab and in-app switches on the same page instead of reloading";
  return items[0].title;
}

function buildPlan(findings, llmSummaries = [], options = {}) {
  const list = Array.isArray(findings) ? findings.slice() : [];
  const counts = countBySeverity(list);
  const pages = [...new Set(list.map((item) => item.url).filter(Boolean))];
  const view = options.view === "page" ? "page" : "session";
  const reviewed = options.reviewed != null ? Boolean(options.reviewed) : pages.length > 0;
  const grade = gradeFromFindings(list, { reviewed });
  const worst = SEVERITIES.find((name) => counts[name] > 0) || null;

  const groups = new Map();
  for (const finding of list) {
    const key = groupKey(finding);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(finding);
  }

  const fixes = [...groups.entries()]
    .map(([key, items]) => {
      items.sort((a, b) => (RANK[a.severity] ?? 9) - (RANK[b.severity] ?? 9));
      const top = items[0];
      return {
        severity: top.severity,
        title: groupedTitle(key, items),
        why: top.description,
        do: top.recommendation || "Apply a defensive control for this finding.",
        count: items.length,
        pages: [...new Set(items.map((item) => item.url).filter(Boolean))],
      };
    })
    .sort((a, b) => (RANK[a.severity] ?? 9) - (RANK[b.severity] ?? 9));

  let risk = "No findings";
  if (worst === "critical") risk = "Urgent";
  else if (worst === "high") risk = "Needs work";
  else if (worst === "medium") risk = "Harden the site";
  else if (worst) risk = "Minor";

  const bits = SEVERITIES.filter((name) => counts[name]).map((name) => `${counts[name]} ${name}`);
  const parts = [];
  if (!list.length) {
    parts.push(
      view === "page"
        ? "No issues on this page yet."
        : "No issues yet. Open a page to start a review."
    );
  } else {
    const where = view === "page" ? "This page" : "This session";
    parts.push(
      `${where} has ${bits.join(", ")} finding${list.length === 1 ? "" : "s"}` +
        (view === "session" && pages.length ? ` across ${pages.length} page${pages.length === 1 ? "" : "s"}` : "") +
        "."
    );
    if (fixes[0]) parts.push(`Start with: ${fixes[0].title}.`);
  }
  for (const extra of llmSummaries) {
    if (extra && extra.text) parts.push(extra.text);
  }

  return {
    risk,
    worst,
    counts,
    pages,
    grade,
    view,
    summary: parts.join(" "),
    fixes,
  };
}

function buildQualityPlan(findings, llmSummaries = [], options = {}) {
  const list = Array.isArray(findings) ? findings.slice() : [];
  const counts = countBySeverity(list);
  const pages = [...new Set(list.map((item) => item.url).filter(Boolean))];
  const view = options.view === "page" ? "page" : "session";
  const reviewed = options.reviewed != null ? Boolean(options.reviewed) : pages.length > 0;
  const score = qualityScore(list, { reviewed });
  const worst = score.worst || SEVERITIES.find((name) => counts[name] > 0) || null;

  const groups = new Map();
  for (const finding of list) {
    const key = groupKey(finding);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(finding);
  }

  const fixes = [...groups.entries()]
    .map(([key, items]) => {
      items.sort((a, b) => (RANK[a.severity] ?? 9) - (RANK[b.severity] ?? 9));
      const top = items[0];
      return {
        severity: top.severity,
        title: groupedTitle(key, items),
        why: top.description,
        do: top.recommendation || "Fix this so the page works for people using it.",
        count: items.length,
        pages: [...new Set(items.map((item) => item.url).filter(Boolean))],
      };
    })
    .sort((a, b) => (RANK[a.severity] ?? 9) - (RANK[b.severity] ?? 9));

  const bits = SEVERITIES.filter((name) => counts[name]).map((name) => `${counts[name]} ${name}`);
  const parts = [];
  if (!list.length) {
    parts.push(
      view === "page"
        ? "No quality issues on this page yet."
        : "No quality issues yet. Open a page to check whether it works."
    );
  } else {
    const where = view === "page" ? "This page" : "This session";
    parts.push(
      `${where} has ${bits.join(", ")} quality issue${list.length === 1 ? "" : "s"}` +
        (view === "session" && pages.length ? ` across ${pages.length} page${pages.length === 1 ? "" : "s"}` : "") +
        "."
    );
    if (fixes[0]) parts.push(`Start with: ${fixes[0].title}.`);
  }
  for (const extra of llmSummaries) {
    if (extra && extra.text) parts.push(extra.text);
  }

  return {
    risk: score.label,
    worst,
    counts,
    pages,
    score,
    view,
    summary: parts.join(" "),
    fixes,
  };
}

function tagFixes(fixes, lane) {
  return (fixes || []).map((item) => ({ ...item, lane }));
}

function mergeFixes(securityFixes, qualityFixes) {
  return [...tagFixes(securityFixes, "security"), ...tagFixes(qualityFixes, "quality")].sort(
    (a, b) => (RANK[a.severity] ?? 9) - (RANK[b.severity] ?? 9)
  );
}

function buildLayman(security, quality) {
  const bits = [];
  const letter = security && security.grade && security.grade.letter;
  if (letter === "F") bits.push("This site would not pass a basic security check.");
  else if (letter) bits.push(`The security grade is ${letter}.`);
  if (security && security.fixes && security.fixes[0]) {
    bits.push(`The first security job is: ${security.fixes[0].title}.`);
  }
  const qualityLabel = quality && quality.score && quality.score.label;
  if (qualityLabel === "Needs work") {
    bits.push("People using it may hit broken pieces, confusing controls, or pages that reload when a tab is clicked.");
  } else if (qualityLabel === "Pass") {
    bits.push("The pages that were opened mostly work.");
  }
  if (quality && quality.fixes && quality.fixes[0]) {
    bits.push(`The first usability job is: ${quality.fixes[0].title}.`);
  }
  if (!bits.length) return "Nothing to explain yet. Open a page and click around.";
  return bits.join(" ");
}

function buildAgentPrompt(security, quality, options = {}) {
  const pages = [...new Set([...(security.pages || []), ...(quality.pages || [])])];
  const fixes = mergeFixes(security.fixes, quality.fixes).slice(0, 16);
  const view = options.view === "page" ? "this page" : "this browsing session";
  const lines = [
    "Implement the BrowseAudit review below.",
    "",
    "Constraints:",
    "- Defensive and quality fixes only. Do not add exploits, payloads, PoCs, or attack steps.",
    "- Do not print or commit secrets. If a secret appeared in HTML or comments, remove it and rotate it; do not repeat the value.",
    "- Do not fill forms, submit credentials, or crawl extra pages.",
    "- Keep the existing product behavior unless a finding requires a change.",
    "",
    `Scope: ${view}.`,
    `Security grade: ${(security.grade && security.grade.letter) || "—"}${(security.grade && security.grade.score != null) ? ` (${security.grade.score}/100)` : ""}.`,
    `Quality: ${(quality.score && quality.score.label) || "—"}.`,
  ];
  if (pages.length) {
    lines.push("Pages:");
    for (const url of pages.slice(0, 12)) lines.push(`- ${url}`);
  }
  lines.push("", "Work through these changes in order:", "");
  if (!fixes.length) {
    lines.push("- No concrete fixes were recorded.");
  } else {
    fixes.forEach((item, index) => {
      lines.push(`${index + 1}. [${item.lane || "security"} / ${item.severity}] ${item.title}`);
      if (item.do) lines.push(`   ${item.do}`);
      if (item.pages && item.pages.length) lines.push(`   Pages: ${item.pages.slice(0, 6).join(", ")}`);
      lines.push("");
    });
  }
  lines.push("When you are done, summarize what changed and what still needs a human.");
  return lines.join("\n");
}

function buildOverallPlan(securityFindings, qualityFindings, summaries = {}, options = {}) {
  const security = buildPlan(securityFindings, summaries.security || [], options);
  const quality = buildQualityPlan(qualityFindings, summaries.quality || [], options);
  const fixes = mergeFixes(security.fixes, quality.fixes);
  const summaryParts = [security.summary];
  if (quality.fixes.length) summaryParts.push(quality.summary);
  return {
    ...security,
    quality: quality.score,
    qualitySummary: quality.summary,
    qualityFixes: quality.fixes,
    fixes,
    summary: summaryParts.filter(Boolean).join(" "),
    layman: buildLayman(security, quality),
    agentPrompt: buildAgentPrompt(security, quality, options),
  };
}

module.exports = {
  buildPlan,
  buildQualityPlan,
  buildOverallPlan,
  buildLayman,
  buildAgentPrompt,
  mergeFixes,
  countBySeverity,
  RANK,
  groupKey,
};
