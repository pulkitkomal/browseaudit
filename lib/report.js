const { buildOverallPlan } = require("./plan");
const { uniqueCookies } = require("./inventory");
const { samePage } = require("./urls");

function flag(ok) {
  return ok ? "yes" : "no";
}

function splitFindings(session, pageUrl) {
  const allFindings = pageUrl
    ? session.findings.filter((item) => samePage(item.url, pageUrl))
    : session.findings;
  const summaries = pageUrl
    ? session.llmSummaries.filter((item) => samePage(item.url, pageUrl))
    : session.llmSummaries;
  const pages = pageUrl
    ? session.pageList().filter((item) => samePage(item.url, pageUrl))
    : session.pageList();
  return {
    security: allFindings.filter((item) => item.lane !== "quality"),
    quality: allFindings.filter((item) => item.lane === "quality"),
    securitySummaries: summaries.filter((item) => (item.kind || "security") !== "quality"),
    qualitySummaries: summaries.filter((item) => item.kind === "quality"),
    pages,
    view: pageUrl ? "page" : "session",
  };
}

function overallFromSession(session, options = {}) {
  const pageUrl = options.page || "";
  const split = splitFindings(session, pageUrl);
  return {
    ...split,
    pageUrl,
    overall: buildOverallPlan(split.security, split.quality, {
      security: split.securitySummaries,
      quality: split.qualitySummaries,
    }, {
      view: split.view,
      reviewed: split.pages.length > 0,
    }),
  };
}

function findingBlock(item) {
  const lines = [`### [${item.severity}] ${item.title}`, ""];
  if (item.lane) lines.push(`- Lane: ${item.lane}`);
  if (item.url) lines.push(`- Page: ${item.url}`);
  if (item.source) lines.push(`- Source: ${item.source}`);
  if (item.cwe) lines.push(`- ${item.cwe}`);
  if (item.description) lines.push(`- ${item.description}`);
  if (item.evidence) lines.push(`- Evidence: ${item.evidence}`);
  if (item.recommendation) lines.push(`- Fix: ${item.recommendation}`);
  lines.push("");
  return lines;
}

function buildReport(session, options = {}) {
  const { overall, security, quality, pages, pageUrl } = overallFromSession(session, options);
  if (options.brief) {
    overall.layman = options.brief.layman || overall.layman;
    overall.agentPrompt = options.brief.agentPrompt || overall.agentPrompt;
    overall.summary = options.brief.summary || overall.summary;
    if (Array.isArray(options.brief.fixes) && options.brief.fixes.length) {
      overall.fixes = options.brief.fixes;
    }
  }
  const cookies = uniqueCookies(pages);
  const generated = new Date().toISOString();
  const source = options.source || "heuristic";
  const lines = [
    "# BrowseAudit report",
    "",
    `- Generated: ${generated}`,
    `- View: ${pageUrl ? `this page (${pageUrl})` : "whole session"}`,
    `- Grade: ${overall.grade.letter || "—"} (${overall.grade.score == null ? "n/a" : overall.grade.score})`,
    `- Risk: ${overall.risk}`,
    `- Quality: ${(overall.quality && overall.quality.label) || "—"}`,
    `- Scope: ${session.scopeList().join(", ") || "(empty)"}`,
    `- Written by: ${source === "openai" ? options.model || "OpenAI" : "local checks"}`,
    "",
    "## In plain language",
    "",
    overall.layman || "No plain-language summary yet.",
    "",
    "## Prompt for an implementing agent",
    "",
    "Copy the block below into Cursor or another coding agent.",
    "",
    "```",
    overall.agentPrompt || "No agent prompt yet.",
    "```",
    "",
    "## Summary",
    "",
    overall.summary,
    "",
    "## What to fix",
    "",
  ];

  if (!overall.fixes.length) {
    lines.push("No fixes yet.");
  } else {
    overall.fixes.forEach((item, index) => {
      lines.push(`${index + 1}. **[${item.lane || "security"} / ${item.severity}] ${item.title}**`);
      lines.push(`   ${item.do}`);
      if (item.pages && item.pages.length) lines.push(`   Pages: ${item.pages.join(", ")}`);
      lines.push("");
    });
  }

  lines.push("## Security findings", "");
  if (!security.length) lines.push("None.", "");
  else security.forEach((item) => lines.push(...findingBlock(item)));

  lines.push("## Quality findings", "");
  if (!quality.length) lines.push("None.", "");
  else quality.forEach((item) => lines.push(...findingBlock(item)));

  lines.push("## Security headers", "");
  if (!pages.length) {
    lines.push("No pages recorded.");
  } else {
    lines.push("| Page | Header | Present | Value |");
    lines.push("| --- | --- | --- | --- |");
    for (const page of pages) {
      for (const row of page.headers || []) {
        const value = String(row.value || "").replace(/\|/g, "\\|").slice(0, 160);
        lines.push(`| ${page.url} | ${row.name} | ${flag(row.present)} | ${value} |`);
      }
    }
  }

  lines.push("", "## Cookies", "");
  lines.push("Names and flags only. Values are not recorded.");
  lines.push("");
  if (!cookies.length) {
    lines.push("No cookies recorded.");
  } else {
    lines.push("| Name | Host | Path | Secure | HttpOnly | SameSite |");
    lines.push("| --- | --- | --- | --- | --- | --- |");
    for (const cookie of cookies) {
      lines.push(
        `| ${cookie.name} | ${cookie.host} | ${cookie.path} | ${flag(cookie.secure)} | ${flag(cookie.httpOnly)} | ${cookie.sameSite || "(unset)"} |`
      );
    }
  }

  lines.push("");
  return lines.join("\n");
}

module.exports = { buildReport, overallFromSession };
