// abpq-redirections
// - abpq.cc/<chemin>       → redirection lue dans KV, sinon repli sur la home (service binding HOME)
// - redirections.abpq.cc   → dashboard (liste, documentation, ajout, édition), protégé par mot de passe
//
// Bindings : REDIRECTS (KV), HOME (service abpq-home)
// Secrets  : SESSION_KEY (signature des cookies), SETUP_TOKEN (premier réglage du mot de passe)
//
// Tout le code est dans createApp() pour pouvoir être déployé tel quel via l'API Cloudflare.

function createApp() {
  const DASH_HOST = 'redirections.abpq.cc';
  const KEY = 'redirects'; // { [slug]: { slug, target, description, group, status, createdAt, updatedAt } }
  const RESERVED = new Set(['', 'shots', 'admin', 'index.html', 'favicon.ico', 'robots.txt']);
  const SESSION_DAYS = 30;
  const enc = new TextEncoder();

  // ---------- utilitaires ----------
  const json = (data, status = 200, headers = {}) =>
    new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
  const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const normSlug = (s) => String(s || '').trim().replace(/^\/+|\/+$/g, '').toLowerCase();
  const validSlug = (s) => /^[a-z0-9][a-z0-9._\-\/]{0,79}$/.test(s) && !RESERVED.has(s.split('/')[0]);
  const validUrl = (u) => { try { const x = new URL(u); return x.protocol === 'https:' || x.protocol === 'http:'; } catch { return false; } };

  async function loadAll(env, cacheTtl) {
    const opts = cacheTtl ? { type: 'json', cacheTtl } : { type: 'json' };
    return (await env.REDIRECTS.get(KEY, opts)) || {};
  }
  const saveAll = (env, data) => env.REDIRECTS.put(KEY, JSON.stringify(data));

  async function hmac(env, msg) {
    const key = await crypto.subtle.importKey('raw', enc.encode(env.SESSION_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return b64u(await crypto.subtle.sign('HMAC', key, enc.encode(msg)));
  }
  async function pbkdf2(password, salt) {
    const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    return b64u(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 100000 }, key, 256));
  }
  function timingSafeEq(a, b) {
    if (a.length !== b.length) return false;
    let r = 0;
    for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return r === 0;
  }
  async function makeSession(env) {
    const exp = Date.now() + SESSION_DAYS * 864e5;
    const sig = await hmac(env, 'sess.' + exp);
    return `s=${exp}.${sig}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_DAYS * 86400}`;
  }
  async function isAuthed(request, env) {
    const m = (request.headers.get('cookie') || '').match(/(?:^|;\s*)s=(\d+)\.([\w-]+)/);
    if (!m || Number(m[1]) < Date.now()) return false;
    return timingSafeEq(m[2], await hmac(env, 'sess.' + m[1]));
  }
  const sameOrigin = (request) => {
    const o = request.headers.get('origin');
    return !o || o === 'https://' + DASH_HOST;
  };

  // ---------- redirections publiques (abpq.cc) ----------
  async function handlePublic(request, env, ctx) {
    const url = new URL(request.url);
    const slug = normSlug(decodeURIComponent(url.pathname));
    if (slug && !RESERVED.has(slug.split('/')[0])) {
      const all = await loadAll(env, 30);
      const r = all[slug];
      if (r) {
        const dest = new URL(r.target);
        url.searchParams.forEach((v, k) => { if (!dest.searchParams.has(k)) dest.searchParams.set(k, v); });
        ctx.waitUntil(countHit(env, slug));
        return new Response(null, { status: r.status === 301 ? 301 : 302, headers: { location: dest.toString(), 'cache-control': 'no-store' } });
      }
    }
    return env.HOME.fetch(request);
  }
  async function countHit(env, slug) {
    const k = 'h:' + slug;
    const cur = (await env.REDIRECTS.get(k, { type: 'json' })) || { count: 0 };
    await env.REDIRECTS.put(k, JSON.stringify({ count: (cur.count || 0) + 1, last: new Date().toISOString() }));
  }

  // ---------- API du dashboard ----------
  async function handleApi(request, env, path) {
    const method = request.method;

    if (path === '/api/setup' && method === 'POST') {
      if (await env.REDIRECTS.get('auth')) return json({ error: 'Mot de passe déjà défini.' }, 409);
      const { token, password } = await request.json();
      if (!env.SETUP_TOKEN || !token || !timingSafeEq(String(token), env.SETUP_TOKEN)) return json({ error: 'Lien de configuration invalide.' }, 403);
      if (!password || String(password).length < 10) return json({ error: '10 caractères minimum.' }, 400);
      const salt = b64u(crypto.getRandomValues(new Uint8Array(16)));
      await env.REDIRECTS.put('auth', JSON.stringify({ salt, hash: await pbkdf2(String(password), salt) }));
      return json({ ok: true }, 200, { 'set-cookie': await makeSession(env) });
    }

    if (path === '/api/login' && method === 'POST') {
      const auth = await env.REDIRECTS.get('auth', { type: 'json' });
      if (!auth) return json({ error: 'Aucun mot de passe défini.' }, 409);
      const { password } = await request.json();
      const ok = timingSafeEq(await pbkdf2(String(password || ''), auth.salt), auth.hash);
      if (!ok) { await new Promise((r) => setTimeout(r, 800)); return json({ error: 'Mot de passe incorrect.' }, 401); }
      return json({ ok: true }, 200, { 'set-cookie': await makeSession(env) });
    }

    if (path === '/api/logout' && method === 'POST') {
      return json({ ok: true }, 200, { 'set-cookie': 's=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' });
    }

    if (!(await isAuthed(request, env))) return json({ error: 'Non connecté.' }, 401);

    if (path === '/api/redirects' && method === 'GET') {
      const all = await loadAll(env);
      const list = await Promise.all(Object.values(all).map(async (r) => ({ ...r, hits: (await env.REDIRECTS.get('h:' + r.slug, { type: 'json' })) || { count: 0 } })));
      list.sort((a, b) => (a.group || '').localeCompare(b.group || '') || a.slug.localeCompare(b.slug));
      return json({ redirects: list });
    }

    const m = path.match(/^\/api\/redirects(?:\/(.+))?$/);
    if (m && (method === 'POST' || method === 'PUT' || method === 'DELETE')) {
      const all = await loadAll(env);
      const current = m[1] ? normSlug(decodeURIComponent(m[1])) : null;

      if (method === 'DELETE') {
        if (!current || !all[current]) return json({ error: 'Introuvable.' }, 404);
        delete all[current];
        await saveAll(env, all);
        await env.REDIRECTS.delete('h:' + current);
        return json({ ok: true });
      }

      const body = await request.json();
      const slug = normSlug(body.slug);
      const target = String(body.target || '').trim();
      if (!validSlug(slug)) return json({ error: 'Chemin invalide (lettres, chiffres, - _ . /).' }, 400);
      if (!validUrl(target)) return json({ error: 'URL de destination invalide.' }, 400);
      if (method === 'POST' && all[slug]) return json({ error: `/${slug} existe déjà.` }, 409);
      if (method === 'PUT' && (!current || !all[current])) return json({ error: 'Introuvable.' }, 404);
      if (method === 'PUT' && slug !== current && all[slug]) return json({ error: `/${slug} existe déjà.` }, 409);

      const now = new Date().toISOString();
      const prev = method === 'PUT' ? all[current] : null;
      const rec = {
        slug, target,
        description: String(body.description || '').trim().slice(0, 500),
        group: String(body.group || '').trim().slice(0, 60),
        status: Number(body.status) === 301 ? 301 : 302,
        createdAt: prev ? prev.createdAt : now,
        updatedAt: now,
      };
      if (prev && slug !== current) {
        delete all[current];
        const h = await env.REDIRECTS.get('h:' + current);
        if (h) { await env.REDIRECTS.put('h:' + slug, h); await env.REDIRECTS.delete('h:' + current); }
      }
      all[slug] = rec;
      await saveAll(env, all);
      return json({ ok: true, redirect: rec });
    }

    return json({ error: 'Not found' }, 404);
  }

  async function handleDashboard(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      if (request.method !== 'GET' && !sameOrigin(request)) return json({ error: 'Origine refusée.' }, 403);
      return handleApi(request, env, url.pathname);
    }
    if (url.pathname === '/' || url.pathname === '/setup') {
      const hasAuth = !!(await env.REDIRECTS.get('auth'));
      const authed = hasAuth && (await isAuthed(request, env));
      const mode = authed ? 'app' : hasAuth ? 'login' : url.pathname === '/setup' ? 'setup' : 'closed';
      return new Response(page(mode), {
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          'x-frame-options': 'DENY',
          'referrer-policy': 'no-referrer',
          'x-robots-tag': 'noindex, nofollow',
        },
      });
    }
    return new Response('Not found', { status: 404 });
  }

  // ---------- interface ----------
  function page(mode) {
    return `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#000000">
<title>Redirections — abpq.cc</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='14' fill='%231c1c1e'/><path d='M18 40h20m0 0-7-7m7 7-7 7M46 24H26m0 0 7-7m-7 7 7 7' stroke='%230A84FF' stroke-width='5' fill='none' stroke-linecap='round' stroke-linejoin='round'/></svg>">
<style>
:root{
  --bg:#000;--panel:#1c1c1e;--panel2:#2c2c2e;--line:rgba(84,84,88,.55);--line2:rgba(84,84,88,.3);
  --fg:#f5f5f7;--fg2:#98989d;--fg3:#636366;--blue:#0A84FF;--green:#30D158;--orange:#FF9F0A;--red:#FF453A;
  --sans:-apple-system,BlinkMacSystemFont,"SF Pro Text","SF Pro Display","Helvetica Neue",Inter,system-ui,sans-serif;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,"JetBrains Mono",monospace;
}
*{box-sizing:border-box}
[hidden]{display:none!important}
html,body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 var(--sans);-webkit-font-smoothing:antialiased;letter-spacing:-.01em}
button,input,select,textarea{font:inherit;color:inherit;letter-spacing:inherit}
a{color:var(--blue);text-decoration:none}
.mono{font-family:var(--mono);letter-spacing:0}
.app{display:grid;grid-template-columns:248px 1fr;min-height:100vh}
aside{border-right:1px solid var(--line2);padding:20px 12px;position:sticky;top:0;height:100vh;background:rgba(28,28,30,.5);backdrop-filter:saturate(180%) blur(20px)}
.brand{display:flex;align-items:center;gap:10px;padding:4px 10px 20px;font-weight:600;font-size:15px}
.brand i{width:28px;height:28px;border-radius:7px;background:linear-gradient(180deg,#2c2c2e,#1c1c1e);border:1px solid var(--line);display:grid;place-items:center;font-style:normal;color:var(--blue);font-size:15px}
.brand small{display:block;color:var(--fg2);font-weight:400;font-size:12px}
.side-h{font-size:11px;font-weight:600;color:var(--fg3);text-transform:uppercase;letter-spacing:.06em;padding:14px 10px 6px}
.side a{display:flex;justify-content:space-between;align-items:center;padding:7px 10px;border-radius:8px;color:var(--fg);font-size:14px;cursor:pointer}
.side a:hover{background:rgba(255,255,255,.05)}
.side a.on{background:rgba(10,132,255,.18);color:#fff}
.side a span:last-child{color:var(--fg2);font-size:12px;font-variant-numeric:tabular-nums}
main{padding:28px clamp(16px,3vw,40px) 60px;min-width:0}
.top{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.top h1{margin:0;font-size:28px;font-weight:700;letter-spacing:-.025em;flex:1 1 auto}
.search{position:relative;flex:0 1 280px}
.search input{width:100%;height:34px;border-radius:9px;border:1px solid transparent;background:var(--panel2);padding:0 12px 0 32px;outline:none}
.search input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(10,132,255,.25)}
.search svg{position:absolute;left:10px;top:9px;opacity:.5}
.btn{height:34px;padding:0 14px;border-radius:9px;border:0;background:var(--panel2);cursor:pointer;font-weight:500;display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.btn:hover{filter:brightness(1.2)}
.btn.primary{background:var(--blue);color:#fff}
.btn.danger{background:rgba(255,69,58,.15);color:var(--red)}
.btn.ghost{background:transparent;color:var(--fg2)}
.btn:focus-visible,.icon:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:28px}
.stat{background:var(--panel);border-radius:14px;padding:14px 16px}
.stat b{display:block;font-size:26px;font-weight:600;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.stat span{font-size:12px;color:var(--fg2)}
.group{margin-bottom:28px}
.group h2{font-size:13px;font-weight:600;color:var(--fg2);margin:0 0 8px 16px;text-transform:uppercase;letter-spacing:.05em}
.list{background:var(--panel);border-radius:14px;overflow:hidden}
.row{display:grid;grid-template-columns:minmax(150px,1fr) minmax(200px,1.6fr) 90px 112px;gap:16px;align-items:center;padding:14px 16px;border-top:1px solid var(--line2)}
.row:first-child{border-top:0}
.row:hover{background:rgba(255,255,255,.025)}
.slug{font-family:var(--mono);font-size:14px;color:#fff;display:flex;align-items:center;gap:8px;min-width:0}
.slug code{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.badge{font:600 10px var(--mono);padding:2px 6px;border-radius:5px;background:rgba(48,209,88,.15);color:var(--green);flex:none}
.badge.p{background:rgba(255,159,10,.15);color:var(--orange)}
.dest{min-width:0}
.dest a{font-family:var(--mono);font-size:12.5px;color:var(--fg2);display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dest a:hover{color:var(--blue)}
.desc{font-size:14px;color:var(--fg);margin-top:3px}
.desc:empty{display:none}
.hits{text-align:right;font-variant-numeric:tabular-nums}
.hits b{display:block;font-weight:500}
.hits span{font-size:11.5px;color:var(--fg3)}
.acts{display:flex;justify-content:flex-end;gap:4px}
.icon{width:32px;height:32px;border-radius:8px;border:0;background:transparent;color:var(--fg2);cursor:pointer;display:grid;place-items:center}
.icon:hover{background:var(--panel2);color:var(--fg)}
.empty{padding:48px 16px;text-align:center;color:var(--fg2)}
.howto{margin-top:36px;color:var(--fg2);font-size:13px;line-height:1.6;max-width:720px}
.howto b{color:var(--fg)}
dialog{border:0;padding:0;background:transparent;color:var(--fg);max-width:min(560px,calc(100vw - 32px));width:100%}
dialog::backdrop{background:rgba(0,0,0,.6);backdrop-filter:blur(6px)}
.sheet{background:rgba(44,44,46,.92);backdrop-filter:saturate(180%) blur(30px);border:1px solid var(--line);border-radius:16px;padding:22px;box-shadow:0 30px 80px rgba(0,0,0,.6)}
.sheet h3{margin:0 0 18px;font-size:17px;font-weight:600}
.field{margin-bottom:14px}
.field label{display:block;font-size:12px;font-weight:500;color:var(--fg2);margin-bottom:6px}
.field input,.field textarea{width:100%;border-radius:9px;border:1px solid var(--line);background:rgba(0,0,0,.35);padding:9px 11px;outline:none}
.field textarea{min-height:76px;resize:vertical}
.field input:focus,.field textarea:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(10,132,255,.25)}
.prefix{display:flex;align-items:center;border-radius:9px;border:1px solid var(--line);background:rgba(0,0,0,.35)}
.prefix:focus-within{border-color:var(--blue);box-shadow:0 0 0 3px rgba(10,132,255,.25)}
.prefix span{padding-left:11px;color:var(--fg3);font-family:var(--mono);font-size:13px}
.prefix input{border:0;background:transparent;box-shadow:none!important;padding-left:2px;font-family:var(--mono);font-size:13px}
.seg{display:inline-flex;background:rgba(0,0,0,.35);border-radius:9px;padding:2px;border:1px solid var(--line)}
.seg button{border:0;background:transparent;padding:5px 14px;border-radius:7px;cursor:pointer;font-size:13px;color:var(--fg2)}
.seg button.on{background:var(--panel2);color:#fff;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.hint{font-size:12px;color:var(--fg3);margin-top:6px}
.err{color:var(--red);font-size:13px;min-height:18px;margin:4px 0 10px}
.foot{display:flex;gap:8px;justify-content:flex-end;align-items:center}
.foot .btn.danger{margin-right:auto}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(20px);opacity:0;background:rgba(44,44,46,.95);backdrop-filter:blur(20px);border:1px solid var(--line);padding:10px 16px;border-radius:12px;font-size:14px;transition:all .25s;pointer-events:none}
.toast.on{opacity:1;transform:translateX(-50%) translateY(0)}
.auth{min-height:100vh;display:grid;place-items:center;padding:24px}
.auth .sheet{width:100%;max-width:360px;text-align:center}
.auth .logo{width:56px;height:56px;margin:4px auto 14px;border-radius:14px;background:var(--panel2);display:grid;place-items:center;color:var(--blue);font-size:26px}
.auth p{color:var(--fg2);font-size:13px;margin:0 0 18px}
.auth input{width:100%;height:40px;border-radius:10px;border:1px solid var(--line);background:rgba(0,0,0,.35);padding:0 12px;outline:none;text-align:center;margin-bottom:10px}
.auth input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(10,132,255,.25)}
.auth .btn{width:100%;justify-content:center;height:40px}
@media (max-width:860px){
  .app{grid-template-columns:1fr}
  aside{position:static;height:auto;border-right:0;border-bottom:1px solid var(--line2)}
  .side-h,.side{display:none}
  .row{grid-template-columns:1fr auto;gap:8px 12px}
  .dest{grid-column:1/-1;order:3}
  .hits{display:none}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
</head>
<body>
${mode === 'app' ? appHtml() : authHtml(mode)}
<div class="toast" id="toast" role="status" aria-live="polite"></div>
<script>
const MODE = ${JSON.stringify(mode)};
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function toast(msg){const t=$('#toast');t.textContent=msg;t.classList.add('on');clearTimeout(t._h);t._h=setTimeout(()=>t.classList.remove('on'),1800);}
async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { 'content-type': 'application/json' }, body: opts.body ? JSON.stringify(opts.body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && MODE === 'app') { location.reload(); throw new Error('Session expirée'); }
  if (!res.ok) throw new Error(data.error || 'Erreur ' + res.status);
  return data;
}
${mode === 'app' ? appJs() : authJs()}
</script>
</body>
</html>`;
  }

  function authHtml(mode) {
    if (mode === 'closed') {
      return `<div class="auth"><div class="sheet"><div class="logo">⇄</div><h3>Redirections</h3><p>Accès non configuré. Ouvre le lien de configuration fourni.</p></div></div>`;
    }
    const setup = mode === 'setup';
    return `<div class="auth"><form class="sheet" id="authForm">
<div class="logo">⇄</div>
<h3>${setup ? 'Choisir un mot de passe' : 'Redirections'}</h3>
<p>${setup ? '10 caractères minimum. Il protégera ce dashboard.' : 'abpq.cc'}</p>
<input type="password" id="pw" autocomplete="${setup ? 'new-password' : 'current-password'}" placeholder="Mot de passe" required minlength="${setup ? 10 : 1}" autofocus aria-label="Mot de passe">
${setup ? '<input type="password" id="pw2" autocomplete="new-password" placeholder="Confirmer" required aria-label="Confirmer le mot de passe">' : ''}
<div class="err" id="err"></div>
<button class="btn primary" type="submit">${setup ? 'Enregistrer' : 'Se connecter'}</button>
</form></div>`;
  }
  function authJs() {
    return `
$('#authForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = $('#pw').value, err = $('#err'); err.textContent = '';
  try {
    if (MODE === 'setup') {
      if (pw !== $('#pw2').value) { err.textContent = 'Les deux mots de passe diffèrent.'; return; }
      const token = new URLSearchParams(location.search).get('token');
      await api('/api/setup', { method: 'POST', body: { token, password: pw } });
      location.replace('/');
    } else {
      await api('/api/login', { method: 'POST', body: { password: pw } });
      location.reload();
    }
  } catch (x) { err.textContent = x.message; }
});`;
  }

  function appHtml() {
    return `<div class="app">
<aside>
  <div class="brand"><i>⇄</i><div>Redirections<small>abpq.cc</small></div></div>
  <div class="side-h">Groupes</div>
  <nav class="side" id="side" aria-label="Groupes"></nav>
</aside>
<main>
  <div class="top">
    <h1 id="title">Toutes</h1>
    <label class="search"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg><input id="q" type="search" placeholder="Rechercher" aria-label="Rechercher"></label>
    <button class="btn primary" id="add" type="button"><span aria-hidden="true">＋</span> Nouvelle</button>
    <button class="btn ghost" id="logout" type="button">Déconnexion</button>
  </div>
  <div class="stats" id="stats"></div>
  <div id="groups"></div>
  <div class="howto">
    <b>Fonctionnement.</b> Chaque redirection est un chemin de <span class="mono">abpq.cc</span> renvoyé vers une URL.
    Aucune déclaration DNS : le Worker qui sert abpq.cc lit la liste à chaque visite. Un changement est actif en moins d'une minute.
    <b>302</b> (temporaire) est le bon choix pour des puces NFC ou des QR codes : la destination reste modifiable sans cache navigateur.
    <b>301</b> (permanent) seulement pour une adresse qui ne changera plus. Les paramètres d'URL sont transmis à la destination.
  </div>
</main>
</div>
<dialog id="dlg"><form class="sheet" id="form" method="dialog">
  <h3 id="formTitle">Nouvelle redirection</h3>
  <div class="field"><label for="f-slug">Chemin</label><div class="prefix"><span>abpq.cc/</span><input id="f-slug" required autocomplete="off" spellcheck="false" placeholder="co24"></div></div>
  <div class="field"><label for="f-target">Destination</label><input id="f-target" type="url" required placeholder="https://…" spellcheck="false" class="mono"></div>
  <div class="field"><label for="f-desc">Description</label><textarea id="f-desc" placeholder="À quoi sert ce lien, où est-il imprimé ou programmé…"></textarea></div>
  <div class="field"><label for="f-group">Groupe</label><input id="f-group" list="groupList" placeholder="ex. Cousteau d'Or 2024" autocomplete="off"><datalist id="groupList"></datalist></div>
  <div class="field"><label>Type</label><div class="seg" id="f-status" role="radiogroup" aria-label="Type de redirection"><button type="button" data-v="302" class="on" role="radio" aria-checked="true">302 temporaire</button><button type="button" data-v="301" role="radio" aria-checked="false">301 permanente</button></div><div class="hint">302 recommandé pour les puces NFC et QR codes.</div></div>
  <div class="err" id="ferr"></div>
  <div class="foot"><button class="btn danger" type="button" id="del" hidden>Supprimer</button><button class="btn" type="button" id="cancel">Annuler</button><button class="btn primary" type="submit" id="save">Enregistrer</button></div>
</form></dialog>`;
  }

  function appJs() {
    return `
let ALL = [], GROUP = null, EDIT = null, STATUS = 302;
const ICON = {
  copy: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="12" height="12" rx="2.5"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>',
  open: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/></svg>',
  edit: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 20h4L19 9l-4-4L4 16v4z"/></svg>'
};
const fmtDate = (s) => s ? new Date(s).toLocaleDateString('fr-FR', { day: 'numeric', month: 'short', year: '2-digit' }) : 'jamais';
const groupName = (r) => r.group || 'Sans groupe';

async function load() { ALL = (await api('/api/redirects')).redirects; render(); }

function render() {
  const q = $('#q').value.trim().toLowerCase();
  const groups = [...new Set(ALL.map(groupName))].sort((a, b) => a.localeCompare(b));
  $('#side').innerHTML = [['Toutes', null, ALL.length], ...groups.map((g) => [g, g, ALL.filter((r) => groupName(r) === g).length])]
    .map(([label, g, n]) => '<a role="button" tabindex="0" data-g="' + esc(g ?? '') + '" class="' + (GROUP === g ? 'on' : '') + '"><span>' + esc(label) + '</span><span>' + n + '</span></a>').join('');
  $('#groupList').innerHTML = groups.filter((g) => g !== 'Sans groupe').map((g) => '<option value="' + esc(g) + '">').join('');
  $('#title').textContent = GROUP ?? 'Toutes';

  const items = ALL.filter((r) => (GROUP === null || groupName(r) === GROUP) && (!q || [r.slug, r.target, r.description, r.group].join(' ').toLowerCase().includes(q)));
  const hits = items.reduce((s, r) => s + (r.hits.count || 0), 0);
  const last = items.map((r) => r.hits.last).filter(Boolean).sort().pop();
  $('#stats').innerHTML = [[items.length, 'redirections'], [hits, 'visites'], [fmtDate(last), 'dernière visite'], [new Set(items.map(groupName)).size, 'groupes']]
    .map(([b, s]) => '<div class="stat"><b>' + esc(b) + '</b><span>' + s + '</span></div>').join('');

  if (!items.length) { $('#groups').innerHTML = '<div class="list"><div class="empty">' + (ALL.length ? 'Aucun résultat.' : 'Aucune redirection. Crée la première avec « Nouvelle ».') + '</div></div>'; return; }
  const byGroup = {};
  items.forEach((r) => (byGroup[groupName(r)] ||= []).push(r));
  $('#groups').innerHTML = Object.keys(byGroup).sort((a, b) => a.localeCompare(b)).map((g) =>
    '<section class="group"><h2>' + esc(g) + '</h2><div class="list">' + byGroup[g].map(row).join('') + '</div></section>').join('');
}

function row(r) {
  return '<div class="row">' +
    '<div class="slug"><code>/' + esc(r.slug) + '</code><span class="badge' + (r.status === 301 ? ' p' : '') + '">' + r.status + '</span></div>' +
    '<div class="dest"><a href="' + esc(r.target) + '" target="_blank" rel="noopener">→ ' + esc(r.target.replace(/^https?:\\/\\//, '')) + '</a><div class="desc">' + esc(r.description) + '</div></div>' +
    '<div class="hits"><b>' + (r.hits.count || 0) + '</b><span>' + fmtDate(r.hits.last) + '</span></div>' +
    '<div class="acts">' +
      '<button class="icon" type="button" data-copy="' + esc(r.slug) + '" title="Copier https://abpq.cc/' + esc(r.slug) + '" aria-label="Copier le lien">' + ICON.copy + '</button>' +
      '<a class="icon" href="https://abpq.cc/' + esc(r.slug) + '" target="_blank" rel="noopener" title="Tester" aria-label="Tester la redirection">' + ICON.open + '</a>' +
      '<button class="icon" type="button" data-edit="' + esc(r.slug) + '" title="Modifier" aria-label="Modifier">' + ICON.edit + '</button>' +
    '</div></div>';
}

function setStatus(v) { STATUS = v; document.querySelectorAll('#f-status button').forEach((b) => { const on = Number(b.dataset.v) === v; b.classList.toggle('on', on); b.setAttribute('aria-checked', on); }); }
function openForm(r) {
  EDIT = r ? r.slug : null;
  $('#formTitle').textContent = r ? 'Modifier /' + r.slug : 'Nouvelle redirection';
  $('#f-slug').value = r?.slug || ''; $('#f-target').value = r?.target || ''; $('#f-desc').value = r?.description || '';
  $('#f-group').value = r?.group ?? (GROUP && GROUP !== 'Sans groupe' ? GROUP : '');
  setStatus(r?.status || 302); $('#del').hidden = !r; $('#ferr').textContent = '';
  $('#dlg').showModal(); (r ? $('#f-target') : $('#f-slug')).focus();
}

document.addEventListener('click', async (e) => {
  const g = e.target.closest('#side a'); if (g) { GROUP = g.dataset.g || null; render(); return; }
  const c = e.target.closest('[data-copy]'); if (c) { await navigator.clipboard.writeText('https://abpq.cc/' + c.dataset.copy); toast('Lien copié'); return; }
  const ed = e.target.closest('[data-edit]'); if (ed) { openForm(ALL.find((r) => r.slug === ed.dataset.edit)); return; }
  const s = e.target.closest('#f-status button'); if (s) setStatus(Number(s.dataset.v));
});
document.addEventListener('keydown', (e) => { const g = e.target.closest?.('#side a'); if (g && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); g.click(); } });
$('#q').addEventListener('input', render);
$('#add').addEventListener('click', () => openForm(null));
$('#cancel').addEventListener('click', () => $('#dlg').close());
$('#logout').addEventListener('click', async () => { await api('/api/logout', { method: 'POST' }); location.reload(); });
$('#del').addEventListener('click', async () => {
  if (!confirm('Supprimer /' + EDIT + ' ? Les liens ou puces qui pointent dessus afficheront la home.')) return;
  try { await api('/api/redirects/' + encodeURIComponent(EDIT), { method: 'DELETE' }); $('#dlg').close(); toast('Supprimée'); load(); } catch (x) { $('#ferr').textContent = x.message; }
});
$('#form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = { slug: $('#f-slug').value, target: $('#f-target').value, description: $('#f-desc').value, group: $('#f-group').value, status: STATUS };
  try {
    if (EDIT) await api('/api/redirects/' + encodeURIComponent(EDIT), { method: 'PUT', body });
    else await api('/api/redirects', { method: 'POST', body });
    $('#dlg').close(); toast('Enregistrée'); load();
  } catch (x) { $('#ferr').textContent = x.message; }
});
document.addEventListener('keydown', (e) => { if (e.key === 'n' && !e.metaKey && !e.ctrlKey && !$('#dlg').open && document.activeElement.tagName !== 'INPUT') { e.preventDefault(); openForm(null); } if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && !$('#dlg').open) { e.preventDefault(); $('#q').focus(); } });
load();`;
  }

  return {
    async fetch(request, env, ctx) {
      const host = new URL(request.url).hostname;
      if (host === DASH_HOST) return handleDashboard(request, env);
      return handlePublic(request, env, ctx);
    },
  };
}

export default createApp();
