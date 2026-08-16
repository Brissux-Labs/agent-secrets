import { randomBytes } from 'node:crypto';
import type { OneTimeRequest } from './store.js';

/**
 * The secure input form.
 *
 * Server-rendered, single file, no framework, no build step. That is a security
 * decision rather than a minimalist affectation: this page receives the plain
 * value, so every byte of JavaScript that runs on it is attack surface, and
 * every external origin it could talk to is an exfiltration path. The page
 * ships eleven lines of inline script — a reveal toggle and a double-submit
 * guard — and nothing else.
 *
 * Enforced properties (FR-WEB-001 … FR-WEB-012):
 *   - a strict CSP with a per-response nonce; `default-src 'none'` means a
 *     successful HTML injection still cannot load or reach anything;
 *   - `Cache-Control: no-store`, so the value is not written to disk cache and
 *     the page cannot be restored from the back/forward cache;
 *   - `Referrer-Policy: no-referrer`, so the one-time token in the URL is never
 *     sent to another origin;
 *   - masked by default with an explicit reveal control;
 *   - `autocomplete="off"` and `spellcheck="false"`, so the value does not land
 *     in the browser's form history or get sent to a spell-check service;
 *   - a CSRF token bound to the request, checked on submit;
 *   - every interpolated value HTML-escaped, including ones that already passed
 *     the scope grammar — defence in depth costs nothing here.
 */

export interface FormNonces {
  readonly script: string;
  readonly csrf: string;
}

export function newNonces(): FormNonces {
  return {
    script: randomBytes(16).toString('base64'),
    csrf: randomBytes(32).toString('base64url'),
  };
}

export function contentSecurityPolicy(scriptNonce: string): string {
  return [
    "default-src 'none'",
    `script-src 'nonce-${scriptNonce}'`,
    "style-src 'unsafe-inline'",
    "img-src 'none'",
    "font-src 'none'",
    "connect-src 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    "require-trusted-types-for 'script'",
  ].join('; ');
}

export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
  Pragma: 'no-cache',
  Expires: '0',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy':
    'accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
};

export function escapeHtml(input: string): string {
  return input
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export interface RenderFormOptions {
  readonly request: OneTimeRequest;
  readonly token: string;
  readonly nonces: FormNonces;
  readonly maxValueBytes: number;
  readonly secondsRemaining: number;
}

export function renderForm(options: RenderFormOptions): string {
  const { request, token, nonces, maxValueBytes, secondsRemaining } = options;
  const action = request.action === 'create' ? 'Add' : 'Rotate';
  const reference = `${request.project}/${request.environment}/${request.secretName}`;
  const isProduction = request.environment === 'production';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive">
<title>${escapeHtml(action)} ${escapeHtml(request.secretName)} — Agent Secrets</title>
<style>
  :root { color-scheme: light dark; --fg:#111; --bg:#fff; --muted:#5b5b5b; --line:#d8d8d8; --accent:#1a5fb4; --warn:#a33; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e9e9e9; --bg:#151515; --muted:#a0a0a0; --line:#3a3a3a; --accent:#7aa2f7; --warn:#f08; }
  }
  * { box-sizing: border-box; }
  body { margin:0; padding:2rem 1rem; background:var(--bg); color:var(--fg);
         font:16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; }
  main { max-width: 34rem; margin: 0 auto; }
  h1 { font-size:1.25rem; margin:0 0 .25rem; }
  .ref { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.9rem;
         color:var(--muted); word-break: break-all; margin:0 0 1.5rem; }
  label { display:block; font-weight:600; margin-bottom:.4rem; }
  input[type=password], input[type=text] {
    width:100%; padding:.7rem .8rem; font-size:1rem; border:1px solid var(--line);
    border-radius:6px; background:var(--bg); color:var(--fg);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  input:focus-visible { outline:2px solid var(--accent); outline-offset:1px; }
  .row { display:flex; align-items:center; gap:.5rem; margin:.75rem 0 1.5rem; }
  button { padding:.7rem 1.2rem; font-size:1rem; border-radius:6px; border:1px solid var(--line);
           background:var(--accent); color:#fff; cursor:pointer; }
  button[type=button] { background:transparent; color:var(--fg); }
  button:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
  .note { color:var(--muted); font-size:.85rem; margin-top:1.5rem; border-top:1px solid var(--line); padding-top:1rem; }
  .warn { color:var(--warn); font-weight:600; }
</style>
</head>
<body>
<main>
  <h1>${escapeHtml(action)} a secret</h1>
  <p class="ref">${escapeHtml(reference)}</p>

  ${
    isProduction
      ? '<p class="warn" role="alert">This is a production environment. Confirm you intend to write here.</p>'
      : ''
  }

  <form method="POST" action="/v1/input/${encodeURIComponent(token)}" autocomplete="off" id="f">
    <input type="hidden" name="csrf" value="${escapeHtml(nonces.csrf)}">
    <label for="value">Secret value</label>
    <input id="value" name="value" type="password" required autofocus
           autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"
           maxlength="${maxValueBytes}"
           aria-describedby="help">
    <div class="row">
      <button type="button" id="toggle" aria-controls="value" aria-pressed="false">Show value</button>
      <span id="help" class="note" style="border:0;padding:0;margin:0">
        Masked by default. Expires in about ${Math.max(0, Math.round(secondsRemaining))} seconds.
      </span>
    </div>
    <button type="submit" id="submit">Save to vault</button>
  </form>

  <p class="note">
    This page sends the value straight to your vault. It is not logged, not stored here,
    and never shown to an AI model. The link works once and cannot be reused.
  </p>
</main>
<script nonce="${escapeHtml(nonces.script)}">
  var t = document.getElementById('toggle'), v = document.getElementById('value');
  t.addEventListener('click', function () {
    var shown = v.type === 'text';
    v.type = shown ? 'password' : 'text';
    t.textContent = shown ? 'Show value' : 'Hide value';
    t.setAttribute('aria-pressed', String(!shown));
    v.focus();
  });
  // FR-WEB-009: a double click, or a back-then-resubmit, must not fire twice.
  // The server rejects the replay anyway; this keeps the user from seeing a
  // confusing error caused by their own second click.
  document.getElementById('f').addEventListener('submit', function (e) {
    var b = document.getElementById('submit');
    if (b.disabled) { e.preventDefault(); return; }
    b.disabled = true; b.textContent = 'Saving…';
  });
</script>
</body>
</html>`;
}

export function renderResult(options: {
  ok: boolean;
  title: string;
  message: string;
  reference?: string;
}): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(options.title)} — Agent Secrets</title>
<style>
  :root { color-scheme: light dark; --fg:#111; --bg:#fff; --muted:#5b5b5b; }
  @media (prefers-color-scheme: dark) { :root { --fg:#e9e9e9; --bg:#151515; --muted:#a0a0a0; } }
  body { margin:0; padding:3rem 1rem; background:var(--bg); color:var(--fg);
         font:16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; }
  main { max-width:34rem; margin:0 auto; }
  h1 { font-size:1.25rem; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color:var(--muted); word-break:break-all; }
</style>
</head>
<body>
<main>
  <h1>${escapeHtml(options.ok ? '✓' : '✗')} ${escapeHtml(options.title)}</h1>
  <p>${escapeHtml(options.message)}</p>
  ${options.reference ? `<p><code>${escapeHtml(options.reference)}</code></p>` : ''}
  <p>You can close this page.</p>
</main>
</body>
</html>`;
}
