<img src="assets/icon.svg" width="64" height="64" alt="">

# BrowseAudit

Browse a site in a local viewport and get a live security and quality review as
you go.

**Issues** covers headers, cookies, transport, and similar security findings
(A–F grade). **Quality** covers broken assets, JS errors, unusable controls,
document basics, and tab/in-app clicks that reload the whole page (Pass / Needs
work). The two lanes stay separate so a broken image never changes the security
grade.

Heuristic checks always run. With an OpenAI key in **Settings**, each page also
gets a security pass and a usability pass. **What to fix** and **Export** combine
both lanes into an overall plan, a plain-language summary, and a copy-paste
prompt for a coding agent.

Use this only on sites you own or have permission to test. BrowseAudit does not
exploit pages, fill forms, submit credentials, or crawl.

## Quick start

```bash
node server.js
```

Open [http://127.0.0.1:8790](http://127.0.0.1:8790). The viewport starts empty —
paste a URL, or click **Lab** for the Harbor Ledger demo.

With Docker:

```bash
docker compose up -d --build
```

## Configuration

Optional environment variables:

| Variable | Default | Notes |
| --- | --- | --- |
| `PORT` | `8790` | HTTP listen port |
| `OPENAI_API_KEY` | _(empty)_ | Or paste a key in **Settings** |
| `OPENAI_MODEL` | `gpt-4o-mini` | Chat model for review / report |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible API base |

Keys saved in Settings live in `data/settings.json` on that machine and are
gitignored. Cookie values and form field values are never stored or sent to the
model.

## What it reports

### Issues (security)

Transport, security headers, cookie flags, mixed content, password forms on
HTTP, missing CSRF-looking tokens, third-party scripts without SRI, inline event
handlers, secrets in HTML comments, and similar problems. Findings are graded
A–F from distinct issue types; critical findings cap the grade at F.

### Quality (usability)

Failed scripts, styles, fonts, and images; uncaught JavaScript errors; unlabeled
or empty controls; placeholder links; missing `title` / `lang` / viewport; and
**interaction** issues — tab-looking controls and in-app links that reload the
whole document instead of updating in place. Those checks watch what *you*
click; BrowseAudit does not click for you.

### Overall

- **This page** vs **Session** for the list, summary, and grade
- **Scope** allowlist for document hosts (lab is always allowed)
- **Headers & cookies** inventory (names and flags only)
- **What to fix** — security + quality, plain-language blurb, agent prompt
- **Export** — Markdown report; with a key, the layman statement and agent
  prompt are written by the model

## How the viewport works

Many sites refuse to be framed. BrowseAudit loads them through a same-origin
path-based proxy (`/proxy/https/host/path`), reviews the original headers, then
rewrites the HTML so the iframe can show the page. If you expose BrowseAudit on
a public URL, treat it as an open proxy: share carefully and keep session scope
tight.

## License

Use and modify for your own authorized testing. Do not use against systems
without permission.
