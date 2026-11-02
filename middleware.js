// Password gate for the whole site (Vercel Edge Middleware).
// Password lives in the DECK_PASSWORD env var on Vercel, never in the repo.

const COOKIE = 'ccu_auth';
const MAX_AGE = 60 * 60 * 24 * 30;

async function sha256(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function cookieValue(req, name) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
  return m ? m[1] : null;
}

function page(next, error) {
  const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
  return `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Spot</title>
<meta name="robots" content="noindex">
<style>
html,body{margin:0;height:100%;background:#0A0F1E;color:#fff;font-family:-apple-system,"Noto Sans TC",sans-serif}
body{display:flex;align-items:center;justify-content:center}
form{width:min(360px,calc(100vw - 48px));display:flex;flex-direction:column;gap:14px}
.mark{display:flex;align-items:center;gap:12px;margin-bottom:18px}
.mark svg{width:30px;height:auto}.mark b{font-size:26px;letter-spacing:.02em}
label{font-size:13px;color:#9aa3b5}
input{font:inherit;font-size:16px;padding:12px 14px;border-radius:10px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.05);color:#fff;outline:none}
input:focus{border-color:#E81020}
button{font:inherit;font-size:15px;font-weight:700;padding:12px;border:0;border-radius:10px;background:#E81020;color:#fff;cursor:pointer}
.err{font-size:13px;color:#ff6b6b;min-height:16px}
</style></head><body>
<form method="post" action="/login">
<div class="mark"><svg viewBox="0 0 245 349" aria-hidden="true"><path d="M0 118.336H118.336V0C53.2471 0 0 53.2471 0 118.336Z" fill="#BA0003"/><path d="M118.336 118.336H0V236.665C65.0821 236.665 118.336 183.418 118.336 118.336Z" fill="#E20E11"/><path d="M118.336 0V118.336C183.418 118.336 236.672 65.0821 236.672 0H118.336Z" fill="#E20E11"/><path d="M244.777 230.019H126.441V348.355C191.523 348.355 244.777 295.108 244.777 230.019Z" fill="#BA0003"/><path d="M126.441 230.019H244.777V111.683C179.695 111.683 126.441 164.937 126.441 230.019Z" fill="#E20E11"/><path d="M126.441 348.355V230.019C61.3585 230.019 8.10449 283.273 8.10449 348.355H126.441Z" fill="#E20E11"/></svg><b>Spot</b></div>
<label for="pw">請輸入密碼</label>
<input id="pw" name="pw" type="password" autocomplete="current-password" autofocus required>
<input type="hidden" name="next" value="${esc(next)}">
<div class="err">${error ? '密碼不正確' : ''}</div>
<button type="submit">進入</button>
</form>
<script>document.querySelector('[name=next]').value += location.hash;</script>
</body></html>`;
}

function html(body, status, extra = {}) {
  return new Response(body, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...extra },
  });
}

export default async function middleware(req) {
  const password = process.env.DECK_PASSWORD;
  if (!password) return new Response('DECK_PASSWORD is not set', { status: 503 });

  const url = new URL(req.url);
  const token = await sha256(password + '|' + url.hostname);

  if (url.pathname === '/login' && req.method === 'POST') {
    const form = await req.formData();
    const next = String(form.get('next') || '/');
    const safeNext = next.startsWith('/') && !next.startsWith('//') ? next : '/';
    if (form.get('pw') === password) {
      return new Response(null, {
        status: 303,
        headers: {
          location: safeNext,
          'set-cookie': `${COOKIE}=${token}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax`,
          'cache-control': 'no-store',
        },
      });
    }
    return html(page(safeNext, true), 401);
  }

  if (cookieValue(req, COOKIE) === token) {
    return new Response(null, { headers: { 'x-middleware-next': '1' } });
  }

  const next = url.pathname + url.search + url.hash;
  return html(page(next, false), 401);
}
