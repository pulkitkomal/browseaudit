const fs = require("fs");
const path = require("path");

const DATA_DIR = path.join(__dirname, "..", "data");
const SETTINGS_PATH = path.join(DATA_DIR, "settings.json");

const DEFAULT_MODEL = "gpt-4o-mini";
const DEFAULT_BASE = "https://api.openai.com/v1";

const SYSTEM_PROMPT = `You are a defensive web security reviewer.

Given a page snapshot (URL, response headers, cookie flags without values, forms, scripts, comments, and a short HTML excerpt), identify likely security weaknesses.

Rules:
- Only report issues the snapshot actually supports. If you are unsure, say so and set confidence to low or medium.
- Do not invent network traffic, hidden endpoints, or backend behavior you did not see.
- Do not provide exploit payloads, proof-of-concept code, bypass strings, or attack steps.
- Recommendations must be defensive (headers, cookie flags, encoding, CSP, HTTPS, CSRF tokens, SRI).
- Skip issues listed in alreadyFlagged unless you can add material extra context.
- Do not report usability, accessibility, missing alt text, viewport, labels, broken images, or JavaScript errors. Those belong to a separate quality review.
- Prefer concrete, page-specific titles over generic advice.

Return JSON with this shape:
{
  "summary": "one short paragraph",
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "title": "short title",
      "description": "what is wrong and why it matters",
      "evidence": "header, snippet, or field you used",
      "recommendation": "how to fix it defensively",
      "cwe": "CWE-nnn or empty",
      "category": "headers|cookies|forms|dom|transport|disclosure|third-party|general",
      "confidence": "high|medium|low"
    }
  ]
}
Maximum 10 findings, most severe first.`;

const QUALITY_PROMPT = `You are a web quality reviewer.

Given a page snapshot and optional runtime notes (JavaScript errors, unlabeled controls, broken images, tab markup, full-reload navigation), identify problems that would stop a person from using the page. Include tab or in-app controls that load a whole new document instead of updating in place.

Rules:
- Only report issues the snapshot or runtime notes actually support.
- Do not invent network traffic, hidden endpoints, or backend behavior you did not see.
- Do not provide exploit payloads, proof-of-concept code, bypass strings, or attack steps.
- Do not report security issues (headers, cookies, CSRF, CSP, mixed content, XSS, secrets). Those are handled separately.
- Do not recommend filling forms, submitting credentials, or crawling other pages.
- Skip issues listed in alreadyFlagged unless you can add material extra context.

Return JSON with this shape:
{
  "summary": "one short paragraph",
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "title": "short title",
      "description": "what is wrong and why it matters for using the page",
      "evidence": "header, snippet, or field you used",
      "recommendation": "how to make the page work better",
      "category": "function|controls|document|general",
      "confidence": "high|medium|low"
    }
  ]
}
Maximum 8 findings, most severe first.`;

function readSettingsFile() {
  try {
    return JSON.parse(fs.readFileSync(SETTINGS_PATH, "utf8"));
  } catch {
    return {};
  }
}

function writeSettingsFile(settings) {
  fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(SETTINGS_PATH, JSON.stringify(settings, null, 2), { mode: 0o600 });
}

function loadSettings() {
  const saved = readSettingsFile();
  return {
    apiKey: saved.apiKey || process.env.OPENAI_API_KEY || "",
    model: saved.model || process.env.OPENAI_MODEL || DEFAULT_MODEL,
    baseUrl: (saved.baseUrl || process.env.OPENAI_BASE_URL || DEFAULT_BASE).replace(/\/$/, ""),
  };
}

function publicSettings() {
  const settings = loadSettings();
  return {
    configured: Boolean(settings.apiKey),
    model: settings.model,
    baseUrl: settings.baseUrl,
  };
}

function saveSettings(patch) {
  const current = loadSettings();
  const next = {
    apiKey: patch.apiKey != null && patch.apiKey !== "" ? String(patch.apiKey) : current.apiKey,
    model: patch.model ? String(patch.model) : current.model,
    baseUrl: patch.baseUrl ? String(patch.baseUrl).replace(/\/$/, "") : current.baseUrl,
  };
  if (patch.clearKey) next.apiKey = "";
  writeSettingsFile({
    apiKey: next.apiKey,
    model: next.model,
    baseUrl: next.baseUrl === DEFAULT_BASE ? undefined : next.baseUrl,
  });
  return publicSettings();
}

async function openaiJson(settings, body, options = {}) {
  const res = await fetch(`${settings.baseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${settings.apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(options.timeoutMs || 45000),
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`OpenAI returned non-JSON (${res.status})`);
  }
  if (!res.ok) {
    const message = data.error?.message || data.message || `OpenAI HTTP ${res.status}`;
    throw new Error(message);
  }
  return data;
}

function parseFindings(content, options = {}) {
  let parsed = content;
  if (typeof content === "string") {
    const trimmed = content.trim();
    const fence = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
    parsed = JSON.parse(fence ? fence[1] : trimmed);
  }
  const findings = Array.isArray(parsed.findings) ? parsed.findings : [];
  const lane = options.lane === "quality" ? "quality" : "security";
  const limit = lane === "quality" ? 8 : 10;
  return {
    summary: String(parsed.summary || "").slice(0, 600),
    findings: findings.slice(0, limit).map((item) => ({
      ...item,
      source: "openai",
      lane,
      id: `llm:${String(item.title || "finding")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .slice(0, 60)}`,
    })),
  };
}

async function reviewSnapshot(snapshot, alreadyFlagged) {
  const settings = loadSettings();
  if (!settings.apiKey) {
    const err = new Error("No API key configured");
    err.code = "not_configured";
    throw err;
  }
  const data = await openaiJson(settings, {
    model: settings.model,
    temperature: 0.1,
    response_format: { type: "json_object" },
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      {
        role: "user",
        content: JSON.stringify({
          snapshot,
          alreadyFlagged: (alreadyFlagged || []).map((item) => ({
            title: item.title,
            severity: item.severity,
            evidence: item.evidence,
          })),
        }),
      },
    ],
  });
  const content = data.choices?.[0]?.message?.content || "{}";
  const parsed = parseFindings(content, { lane: "security" });
  return {
    ...parsed,
    model: data.model || settings.model,
    usage: data.usage || null,
  };
}

async function reviewQuality(snapshot, alreadyFlagged) {
  const settings = loadSettings();
  if (!settings.apiKey) {
    const err = new Error("No API key configured");
    err.code = "not_configured";
    throw err;
  }
  const data = await openaiJson(settings, {
    model: settings.model,
    temperature: 0.1,
    response_format: { type: "json_object" },
    messages: [
      { role: "system", content: QUALITY_PROMPT },
      {
        role: "user",
        content: JSON.stringify({
          snapshot,
          alreadyFlagged: (alreadyFlagged || []).map((item) => ({
            title: item.title,
            severity: item.severity,
            evidence: item.evidence,
          })),
        }),
      },
    ],
  });
  const content = data.choices?.[0]?.message?.content || "{}";
  const parsed = parseFindings(content, { lane: "quality" });
  return {
    ...parsed,
    model: data.model || settings.model,
    usage: data.usage || null,
  };
}

async function writeFixPlan(plan) {
  const settings = loadSettings();
  if (!settings.apiKey) {
    const err = new Error("No API key configured");
    err.code = "not_configured";
    throw err;
  }
  const data = await openaiJson(settings, {
    model: settings.model,
    temperature: 0.1,
    response_format: { type: "json_object" },
    messages: [
      {
        role: "system",
        content:
          "You write a short overall web-security summary and an ordered defensive fix list. Do not provide exploit payloads, PoCs, or attack steps. Return JSON {\"summary\":\"...\",\"fixes\":[{\"severity\":\"critical|high|medium|low|info\",\"title\":\"...\",\"do\":\"concrete defensive fix\"}]}. At most 12 fixes, most severe first. Merge duplicates.",
      },
      { role: "user", content: JSON.stringify({ currentPlan: plan }) },
    ],
  });
  const content = data.choices?.[0]?.message?.content || "{}";
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    parsed = {};
  }
  return {
    summary: String(parsed.summary || plan.summary || "").slice(0, 800),
    fixes: (Array.isArray(parsed.fixes) ? parsed.fixes : plan.fixes).slice(0, 12).map((item, index) => ({
      severity: item.severity || plan.fixes[index]?.severity || "info",
      title: String(item.title || plan.fixes[index]?.title || "Fix").slice(0, 160),
      do: String(item.do || item.recommendation || plan.fixes[index]?.do || "").slice(0, 600),
    })),
    model: data.model || settings.model,
  };
}

async function writeQualityPlan(plan) {
  const settings = loadSettings();
  if (!settings.apiKey) {
    const err = new Error("No API key configured");
    err.code = "not_configured";
    throw err;
  }
  const data = await openaiJson(settings, {
    model: settings.model,
    temperature: 0.1,
    response_format: { type: "json_object" },
    messages: [
      {
        role: "system",
        content:
          "You write a short overall web-quality summary and an ordered improvement list. Cover broken assets, JavaScript errors, unlabeled controls, and document basics. Do not mix in security-header or cookie-flag work. Do not provide exploit payloads, PoCs, or attack steps. Return JSON {\"summary\":\"...\",\"fixes\":[{\"severity\":\"critical|high|medium|low|info\",\"title\":\"...\",\"do\":\"concrete improvement\"}]}. At most 12 fixes, most severe first. Merge duplicates.",
      },
      { role: "user", content: JSON.stringify({ currentPlan: plan }) },
    ],
  });
  const content = data.choices?.[0]?.message?.content || "{}";
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    parsed = {};
  }
  return {
    summary: String(parsed.summary || plan.summary || "").slice(0, 800),
    fixes: (Array.isArray(parsed.fixes) ? parsed.fixes : plan.fixes).slice(0, 12).map((item, index) => ({
      severity: item.severity || plan.fixes[index]?.severity || "info",
      title: String(item.title || plan.fixes[index]?.title || "Improve").slice(0, 160),
      do: String(item.do || item.recommendation || plan.fixes[index]?.do || "").slice(0, 600),
    })),
    model: data.model || settings.model,
  };
}

function compactPlan(plan) {
  return {
    summary: plan.summary,
    layman: plan.layman,
    risk: plan.risk,
    grade: plan.grade,
    quality: plan.quality,
    pages: (plan.pages || []).slice(0, 12),
    fixes: (plan.fixes || []).slice(0, 16).map((item) => ({
      lane: item.lane || "security",
      severity: item.severity,
      title: item.title,
      do: item.do,
      pages: (item.pages || []).slice(0, 6),
    })),
  };
}

async function writeBrief(plan) {
  const settings = loadSettings();
  if (!settings.apiKey) {
    const err = new Error("No API key configured");
    err.code = "not_configured";
    throw err;
  }
  const data = await openaiJson(
    settings,
    {
      model: settings.model,
      temperature: 0.1,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content:
            "You write an overall website review covering security and quality/usability. Do not provide exploit payloads, PoCs, bypass strings, or attack steps. Do not copy secret values, API keys, passwords, or cookie values; refer to location only. Return JSON {\"summary\":\"technical summary\",\"layman\":\"2-4 plain sentences a non-engineer can understand. No jargon.\",\"agentPrompt\":\"a complete prompt a coding agent can follow to implement the listed fixes. Include constraints: defensive only, no exploits, no crawling, no credential submission, do not print secrets.\",\"fixes\":[{\"lane\":\"security|quality\",\"severity\":\"critical|high|medium|low|info\",\"title\":\"...\",\"do\":\"concrete change\"}]}. At most 16 fixes, most severe first. Merge duplicates. Keep both security and quality work.",
        },
        { role: "user", content: JSON.stringify({ currentPlan: compactPlan(plan) }) },
      ],
    },
    { timeoutMs: 60000 }
  );
  const content = data.choices?.[0]?.message?.content || "{}";
  let parsed;
  try {
    const trimmed = content.trim();
    const fence = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
    parsed = JSON.parse(fence ? fence[1] : trimmed);
  } catch {
    parsed = {};
  }
  const fixes = (Array.isArray(parsed.fixes) ? parsed.fixes : plan.fixes).slice(0, 16).map((item, index) => ({
    lane:
      item.lane === "quality" || item.lane === "security"
        ? item.lane
        : plan.fixes[index]?.lane || "security",
    severity: item.severity || plan.fixes[index]?.severity || "info",
    title: String(item.title || plan.fixes[index]?.title || "Fix").slice(0, 160),
    do: String(item.do || item.recommendation || plan.fixes[index]?.do || "").slice(0, 600),
    pages: item.pages || plan.fixes[index]?.pages || [],
  }));
  return {
    summary: String(parsed.summary || plan.summary || "").slice(0, 1000),
    layman: String(parsed.layman || plan.layman || "").slice(0, 800),
    agentPrompt: String(parsed.agentPrompt || plan.agentPrompt || "").slice(0, 8000),
    fixes,
    model: data.model || settings.model,
  };
}

async function testConnection() {
  const settings = loadSettings();
  if (!settings.apiKey) {
    const err = new Error("No API key configured");
    err.code = "not_configured";
    throw err;
  }
  const data = await openaiJson(settings, {
    model: settings.model,
    temperature: 0,
    max_tokens: 20,
    messages: [
      {
        role: "user",
        content: 'Reply with JSON {"ok":true} and nothing else.',
      },
    ],
  });
  return { ok: true, model: data.model || settings.model };
}

module.exports = {
  loadSettings,
  publicSettings,
  saveSettings,
  reviewSnapshot,
  reviewQuality,
  writeFixPlan,
  writeQualityPlan,
  writeBrief,
  testConnection,
  DEFAULT_MODEL,
};
