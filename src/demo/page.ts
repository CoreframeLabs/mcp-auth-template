import type { DemoClientRegistry } from './clients.js';
import type { ScenarioMeta } from './scenarios.js';

const escapeHtml = (s: string): string =>
    s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/** Where the lead-capture CTA points. Coreframe's contact/consultation page. */
const LEAD_CTA_URL = 'https://coreframe-website-six.vercel.app/#data';

/**
 * The demo page, rendered as a single self-contained document.
 *
 * No build step and no client framework on purpose: this page exists to explain
 * a server, and a bundler in front of it would be more moving parts than the
 * thing being demonstrated.
 */
export function renderDemoPage(scenarios: ScenarioMeta[], registry: DemoClientRegistry): string {
    const cards = scenarios
        .map(
            (s) => `
      <button class="scenario" data-id="${escapeHtml(s.id)}" aria-describedby="desc-${escapeHtml(s.id)}">
        <span class="badge ${s.expectSuccess ? 'ok' : 'deny'}">${s.expectSuccess ? 'should succeed' : 'should be rejected'}</span>
        <strong>${escapeHtml(s.title)}</strong>
        <span id="desc-${escapeHtml(s.id)}" class="expect">${escapeHtml(s.expectation)}</span>
        <span class="why">${escapeHtml(s.rationale)}</span>
      </button>`,
        )
        .join('');

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCP Auth Template — live demo</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #fbfbfd; --fg: #16181d; --muted: #5c6370; --line: #e3e5ea;
    --card: #fff; --ok: #12734a; --okbg: #e7f6ed; --deny: #a4262c; --denybg: #fdeceb;
    --code: #f4f5f7; --accent: #2f5bea;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0f1115; --fg:#e6e8ee; --muted:#9aa3b2; --line:#252a33;
            --card:#161a21; --ok:#4ade80; --okbg:#0f2a1d; --deny:#f87171; --denybg:#2c1416;
            --code:#0c0e12; --accent:#7f9cf5; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }
  .wrap { max-width: 1080px; margin: 0 auto; padding: 2.5rem 1.25rem 5rem; }
  h1 { font-size: 1.9rem; margin:0 0 .4rem; letter-spacing:-.02em; }
  .sub { color:var(--muted); margin:0 0 1.5rem; max-width:70ch; }
  .note { border:1px solid var(--line); border-left:3px solid var(--accent);
          background:var(--card); padding:.9rem 1.1rem; border-radius:8px;
          margin:0 0 2rem; color:var(--muted); max-width:80ch; }
  .note strong { color:var(--fg); }
  h2 { font-size:1.05rem; text-transform:uppercase; letter-spacing:.08em;
       color:var(--muted); margin:2.2rem 0 .9rem; }
  .grid { display:grid; gap:.7rem; grid-template-columns:repeat(auto-fill,minmax(310px,1fr)); }
  .scenario { display:flex; flex-direction:column; gap:.35rem; text-align:left;
              background:var(--card); border:1px solid var(--line); border-radius:10px;
              padding:.95rem 1rem; cursor:pointer; font:inherit; color:inherit;
              transition:border-color .15s, transform .1s; }
  .scenario:hover { border-color:var(--accent); }
  .scenario:active { transform:translateY(1px); }
  .scenario[aria-busy="true"] { opacity:.55; cursor:progress; }
  .badge { align-self:flex-start; font-size:.68rem; text-transform:uppercase;
           letter-spacing:.06em; padding:.15rem .45rem; border-radius:4px; font-weight:600; }
  .badge.ok { background:var(--okbg); color:var(--ok); }
  .badge.deny { background:var(--denybg); color:var(--deny); }
  .expect { color:var(--muted); font-size:.88rem; }
  .why { color:var(--muted); font-size:.8rem; font-style:italic; opacity:.85; }
  #out:empty::after { content:"Pick a scenario above. Each one runs for real against this server.";
                      color:var(--muted); font-size:.9rem; }
  .result { background:var(--card); border:1px solid var(--line); border-radius:10px;
            padding:1.1rem 1.25rem; margin-top:1rem; }
  .summary { border-radius:7px; padding:.7rem .9rem; margin:0 0 1rem; font-weight:500; }
  .summary.ok { background:var(--okbg); color:var(--ok); }
  .summary.deny { background:var(--denybg); color:var(--deny); }
  .entry { border-top:1px solid var(--line); padding:.85rem 0; }
  .entry:first-of-type { border-top:none; }
  .entry h3 { margin:0 0 .3rem; font-size:.92rem; }
  .entry .detail { color:var(--muted); font-size:.86rem; white-space:pre-wrap; margin:.2rem 0; }
  pre { background:var(--code); border:1px solid var(--line); border-radius:6px;
        padding:.65rem .8rem; overflow-x:auto; font-size:.8rem; margin:.4rem 0 0;
        font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .status { display:inline-block; font-weight:600; font-size:.8rem;
            padding:.1rem .45rem; border-radius:4px; }
  .status.s2 { background:var(--okbg); color:var(--ok); }
  .status.s4, .status.s5 { background:var(--denybg); color:var(--deny); }
  code { background:var(--code); padding:.1rem .3rem; border-radius:4px; font-size:.85em; }
  footer { margin-top:3rem; padding-top:1.2rem; border-top:1px solid var(--line);
           color:var(--muted); font-size:.85rem; }
  a { color:var(--accent); }

  /* JSON-RPC / error rendering inside transcripts */
  .frame-label { display:inline-block; font-size:.66rem; text-transform:uppercase;
                 letter-spacing:.06em; font-weight:700; padding:.12rem .4rem;
                 border-radius:4px; margin:.5rem 0 .1rem; background:var(--code);
                 color:var(--muted); border:1px solid var(--line); }
  .frame-label.rpc { color:var(--accent); border-color:var(--accent); }
  .error-boundary { border:1px solid var(--deny); border-left:3px solid var(--deny);
                    background:var(--denybg); border-radius:8px; padding:.7rem .9rem;
                    margin:.5rem 0 0; }
  .error-boundary .err-head { font-weight:700; color:var(--deny); font-size:.85rem;
                              margin:0 0 .3rem; }
  .error-boundary pre { background:transparent; border:none; padding:0; margin:.2rem 0 0; }
  .json-key { color:var(--accent); }
  .json-str { color:var(--ok); }
  .json-num { color:var(--deny); }

  /* Lead-capture overlay */
  #lead { position:fixed; right:1.1rem; bottom:1.1rem; z-index:50; width:min(340px, calc(100vw - 2rem));
          background:var(--card); border:1px solid var(--line); border-radius:14px;
          box-shadow:0 12px 40px rgba(0,0,0,.22); padding:1.1rem 1.15rem 1.15rem;
          transform:translateY(0); transition:transform .25s ease, opacity .25s ease; }
  #lead[hidden] { display:none; }
  #lead .lead-eyebrow { font-size:.68rem; text-transform:uppercase; letter-spacing:.07em;
                        font-weight:700; color:var(--accent); margin:0 0 .35rem; }
  #lead p.lead-copy { margin:0 0 .85rem; font-size:.9rem; line-height:1.5; color:var(--fg); }
  #lead .lead-cta { display:inline-block; background:var(--accent); color:#fff; font-weight:600;
                    font-size:.88rem; text-decoration:none; padding:.55rem .95rem; border-radius:8px;
                    width:100%; text-align:center; box-sizing:border-box; }
  #lead .lead-cta:hover { filter:brightness(1.07); }
  #lead .lead-dismiss { position:absolute; top:.55rem; right:.6rem; background:none; border:none;
                        color:var(--muted); font-size:1.1rem; line-height:1; cursor:pointer;
                        padding:.15rem .3rem; border-radius:5px; }
  #lead .lead-dismiss:hover { background:var(--code); color:var(--fg); }
  #leadFab { position:fixed; right:1.1rem; bottom:1.1rem; z-index:50; background:var(--accent);
             color:#fff; border:none; border-radius:999px; padding:.7rem 1.1rem; font:inherit;
             font-size:.85rem; font-weight:600; cursor:pointer; box-shadow:0 8px 26px rgba(0,0,0,.24); }
  #leadFab[hidden] { display:none; }
  @media (max-width:520px) {
    #lead { right:.6rem; left:.6rem; bottom:.6rem; width:auto; }
    #leadFab { right:.6rem; bottom:.6rem; }
  }
</style>
</head>
<body>
<div class="wrap">
  <h1>MCP Auth Template — live demo</h1>
  <p class="sub">
    A remote <strong>Model Context Protocol</strong> server behind a real OAuth 2.1
    boundary, with clients identified by <strong>Client ID Metadata Documents</strong>
    instead of pre-registration. Every button below performs the real flow against
    this server and shows you the actual HTTP exchange.
  </p>

  <div class="note">
    <strong>This is a demonstration deployment.</strong> The authorization server is a
    mock with in-memory state and ephemeral signing keys, and client identities are
    published by this server rather than by you — a real client would host its own
    metadata document. CIMD resolution is restricted to an allowlist here, because a
    public server that dereferences any URL it is handed is an unauthenticated request
    amplifier. Do not point production clients at it.
  </div>

  <h2>Scenarios</h2>
  <div class="grid">${cards}</div>

  <h2>Result</h2>
  <div id="out"></div>

  <footer>
    Demo client identities:
    ${registry.allowedIds.map((id) => `<a href="${escapeHtml(id)}"><code>${escapeHtml(id)}</code></a>`).join(' &middot; ')}
    <br>
    Discovery: <a href="/.well-known/oauth-protected-resource/mcp"><code>/.well-known/oauth-protected-resource/mcp</code></a>
    &middot; <a href="/.well-known/oauth-authorization-server"><code>/.well-known/oauth-authorization-server</code></a>
    <br><br>
    Source: <a href="https://github.com/CoreframeLabs/mcp-auth-template">github.com/CoreframeLabs/mcp-auth-template</a>
  </footer>
</div>

<!-- Lead-capture overlay -->
<aside id="lead" aria-label="Contact Coreframe Labs">
  <button class="lead-dismiss" id="leadDismiss" aria-label="Dismiss">&times;</button>
  <p class="lead-eyebrow">Coreframe Labs</p>
  <p class="lead-copy">Scaling your company's AI integrations? We help venture-backed teams
     and enterprises build secure, production-grade custom software architectures.
     Let's design your agent infrastructure safely.</p>
  <a class="lead-cta" href="${LEAD_CTA_URL}" target="_blank" rel="noopener">
     Book a 15-minute consultation &rarr;</a>
</aside>
<button id="leadFab" hidden aria-label="Contact Coreframe Labs">Talk to our Core Architects &rarr;</button>

<script>
const out = document.getElementById('out');

function statusClass(s) { return 's' + String(s).charAt(0); }

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

/** Minimal JSON syntax highlighting over already-escaped text. */
function highlightJson(escaped) {
  return escaped
    .replace(/&quot;([^&]*?)&quot;(\\s*:)/g, '<span class="json-key">&quot;$1&quot;</span>$2')
    .replace(/:\\s*&quot;([^&]*?)&quot;/g, ': <span class="json-str">&quot;$1&quot;</span>')
    .replace(/:\\s*(-?\\d+(?:\\.\\d+)?)/g, ': <span class="json-num">$1</span>');
}

/**
 * Normalises a response/request body for display. Streamable HTTP returns
 * JSON-RPC inside an SSE frame ("event: message\\ndata: {…}"), so unwrap that,
 * pretty-print any JSON, and label a JSON-RPC 2.0 frame as such.
 */
function formatBody(raw) {
  if (!raw) return null;
  let text = raw, isRpc = false;

  const sse = /data:\\s*(\\{[\\s\\S]*\\})/.exec(raw);
  const jsonSource = sse ? sse[1] : raw;
  try {
    const obj = JSON.parse(jsonSource);
    isRpc = obj && obj.jsonrpc === '2.0';
    text = JSON.stringify(obj, null, 2);
  } catch (_) { /* not JSON — leave as-is (form body, etc.) */ }

  const label = isRpc ? 'JSON-RPC 2.0' : (sse ? 'SSE frame' : null);
  return { html: highlightJson(escapeHtml(text)), label, isRpc };
}

function renderBody(raw) {
  const f = formatBody(raw);
  if (!f) return '';
  const label = f.label
    ? '<span class="frame-label ' + (f.isRpc ? 'rpc' : '') + '">' + f.label + '</span>'
    : '';
  return label + '<pre>' + f.html + '</pre>';
}

function renderEntry(e) {
  const parts = ['<div class="entry"><h3>' + escapeHtml(e.step) + '</h3>'];
  if (e.detail) parts.push('<p class="detail">' + escapeHtml(e.detail) + '</p>');
  if (e.request) {
    parts.push('<pre>' + escapeHtml(e.request.method + ' ' + e.request.url) + '</pre>');
    if (e.request.body) parts.push(renderBody(e.request.body));
  }
  if (e.response) {
    const isError = e.response.status >= 400;
    const hdrs = e.response.headers
      ? Object.entries(e.response.headers).map(([k,v]) => k + ': ' + v).join('\\n')
      : '';
    parts.push('<p class="detail"><span class="status ' + statusClass(e.response.status) +
      '">HTTP ' + e.response.status + (isError ? ' — rejected' : '') + '</span></p>');
    if (hdrs) parts.push('<pre>' + escapeHtml(hdrs) + '</pre>');
    if (isError) {
      // Structured error boundary: parse the OAuth/JSON-RPC error and present it
      // deliberately rather than dumping a raw string.
      parts.push('<div class="error-boundary"><p class="err-head">' + e.response.status +
        (e.response.status === 401 ? ' Unauthorized' : e.response.status === 403 ? ' Forbidden' : '') +
        '</p>' + (renderBody(e.response.body) || '<pre>' + escapeHtml(e.response.body || '') + '</pre>') +
        '</div>');
    } else if (e.response.body) {
      parts.push(renderBody(e.response.body));
    }
  }
  parts.push('</div>');
  return parts.join('');
}

async function run(button) {
  const id = button.dataset.id;
  document.querySelectorAll('.scenario').forEach(b => b.setAttribute('aria-busy','true'));
  out.innerHTML = '<div class="result"><p class="detail">Running…</p></div>';
  try {
    const res = await fetch('/demo/run/' + encodeURIComponent(id), { method: 'POST' });
    if (res.status === 429) {
      out.innerHTML = '<div class="result"><p class="summary deny">Rate limited — wait a minute and try again.</p></div>';
      return;
    }
    const data = await res.json();
    out.innerHTML = '<div class="result">' +
      '<p class="summary ' + (data.succeeded ? 'ok' : 'deny') + '">' + escapeHtml(data.summary) + '</p>' +
      data.transcript.map(renderEntry).join('') + '</div>';
    out.scrollIntoView({ behavior:'smooth', block:'start' });
  } catch (err) {
    out.innerHTML = '<div class="result"><p class="summary deny">Request failed: ' +
      escapeHtml(err.message) + '</p></div>';
  } finally {
    document.querySelectorAll('.scenario').forEach(b => b.removeAttribute('aria-busy'));
  }
}

document.querySelectorAll('.scenario').forEach(b =>
  b.addEventListener('click', () => run(b)));

// Lead-capture overlay: dismissible, remembered for the session so it does not
// nag while someone works through the scenarios.
(function () {
  const card = document.getElementById('lead');
  const fab = document.getElementById('leadFab');
  const dismiss = document.getElementById('leadDismiss');
  const KEY = 'coreframe-lead-dismissed';
  function collapse() { card.hidden = true; fab.hidden = false; try { sessionStorage.setItem(KEY, '1'); } catch (_) {} }
  function expand() { card.hidden = false; fab.hidden = true; try { sessionStorage.removeItem(KEY); } catch (_) {} }
  let dismissed = false;
  try { dismissed = sessionStorage.getItem(KEY) === '1'; } catch (_) {}
  if (dismissed) collapse();
  dismiss.addEventListener('click', collapse);
  fab.addEventListener('click', expand);
})();
</script>
</body>
</html>`;
}
