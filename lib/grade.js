const PENALTY = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };

function groupId(finding) {
  const id = String(finding.id || finding.title || "");
  const prefix = id.split(":")[0];
  if (
    prefix.startsWith("cookie-") ||
    prefix === "sri-missing" ||
    prefix === "mixed-content" ||
    prefix === "csrf-token-missing" ||
    prefix === "tabnabbing" ||
    prefix === "javascript-url"
  ) {
    return prefix;
  }
  return id || finding.title;
}

function letterForScore(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function gradeFromFindings(findings, options = {}) {
  const reviewed = Boolean(options.reviewed);
  const list = Array.isArray(findings) ? findings : [];
  if (!reviewed && !list.length) {
    return { letter: null, score: null, label: "—", reason: "No pages reviewed yet." };
  }

  const groups = new Map();
  for (const finding of list) {
    const key = groupId(finding);
    const prev = groups.get(key);
    const rank = PENALTY[finding.severity] ?? 0;
    if (!prev || rank > (PENALTY[prev.severity] ?? 0)) groups.set(key, finding);
  }

  let score = 100;
  let worst = null;
  for (const finding of groups.values()) {
    score -= PENALTY[finding.severity] ?? 0;
    if (!worst || (PENALTY[finding.severity] ?? 0) > (PENALTY[worst] ?? 0)) worst = finding.severity;
  }
  score = Math.max(0, Math.min(100, score));
  if (worst === "critical") score = Math.min(score, 59);

  const letter = list.length ? letterForScore(score) : "A";
  return {
    letter,
    score,
    label: letter,
    reason: list.length
      ? `${groups.size} distinct issue${groups.size === 1 ? "" : "s"} scored from ${score}.`
      : "No issues on the pages reviewed.",
  };
}

module.exports = { gradeFromFindings, letterForScore, groupId };
