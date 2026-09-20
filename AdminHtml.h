/*
 * AdminHtml.h
 *
 * The admin console served at GET /admin
 *
 */

#ifndef ADMINHTML_H
#define ADMINHTML_H

static const char kAdminHtml[] = R"RAW(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PoE-Passkey Admin Console</title>
<link rel="icon" href="data:,">
<style nonce="__CSP_NONCE__">
 body{font-family:system-ui,sans-serif;max-width:760px;margin:2em auto;padding:0 1em;color:#222}
 h1{font-size:1.4em;margin-bottom:.15em}
 h2{font-size:1.1em;margin:.2em 0 .4em}
 .sub{color:#555;margin-top:0}
 nav{margin:1.25em 0 0;display:flex;flex-wrap:wrap;gap:.25em}
 nav button{padding:.5em 1em;cursor:pointer;background:#f3f3f3;border:1px solid #bbb;border-bottom:none;border-radius:6px 6px 0 0;font:inherit}
 nav button[aria-selected=true]{background:#fff;border-color:#666;font-weight:600}
 section{border-top:1px solid #999;padding-top:.9em}
 label{display:block;font-weight:600;margin:.75em 0 .2em}
 input{padding:.5em;width:100%;max-width:22em;box-sizing:border-box;font:inherit}
 .act{padding:.45em .9em;cursor:pointer;font:inherit}
 .meta{color:#555;font-size:.9em;margin:.4em 0;display:flex;align-items:center;gap:.75em;flex-wrap:wrap}
 table{border-collapse:collapse;width:100%;margin:.4em 0}
 th,td{text-align:left;padding:.45em .5em;border-bottom:1px solid #e3e3e3;font-size:.95em}
 th{background:#fafafa;font-weight:600}
 td.act{text-align:right}
 td.id{font-family:ui-monospace,monospace;color:#555;font-size:.85em}
 .you{color:#555;font-size:.85em}
.who{color:#555;font-size:.9em}
 .dot{color:#1a7f37;font-weight:700}
 .dash{color:#999}
 .state{font-weight:600}
 .state.off{color:#b3261e}
 .when{color:#555;font-size:.9em}
 .confirm{color:#b3261e;font-weight:600}
 .pop{position:relative;display:inline-block}
 .pop .panel{position:absolute;right:0;top:calc(100% + .4em);z-index:20;background:#fff;border:1px solid #bbb;border-radius:6px;box-shadow:0 2px 10px rgba(0,0,0,.18);padding:.45em .55em;white-space:nowrap;display:none;align-items:center;gap:.5em}
 .pop .panel.open{display:flex}
 #status{margin-top:1em;white-space:pre-wrap}
 #status.err{color:#b3261e}
 footer{margin-top:2em;border-top:1px solid #e3e3e3;padding-top:.75em;color:#555}
 a{color:#0b57d0}
</style>
</head>
<body>
<h1>Admin Console</h1>
<p class="sub">Welcome admin from <strong id="ip">__CLIENT_IP__</strong></p>

<nav role="tablist">
 <button id="tabEnroll" role="tab" aria-selected="true" aria-controls="panelEnroll">Enroll Key</button>
 <button id="tabCreds" role="tab" aria-selected="false" aria-controls="panelCreds">Registered Keys</button>
 <button id="tabIps" role="tab" aria-selected="false" aria-controls="panelIps">Authorized IPs</button>
</nav>

<section id="panelEnroll" role="tabpanel" aria-labelledby="tabEnroll">
 <h2>Enroll a security key</h2>
 <p>The entered email address becomes the credential's identity and appears as the name
    of the security key.</p>
 <label for="email">Email address</label>
 <input id="email" type="email" placeholder="admin@example.com" autocomplete="username">
 <div class="meta"><button id="regBtn" class="act">Enroll key</button></div>
</section>

<section id="panelCreds" role="tabpanel" aria-labelledby="tabCreds" hidden>
 <h2>Registered keys</h2>
 <label for="credSearch">Search</label>
 <input id="credSearch" type="search" placeholder="email or credential ID" autocomplete="off">
 <div class="meta"><span id="credCount">Loading...</span><button id="credSortBtn" class="act">Sort: newest first</button><button id="credRefresh" class="act">Refresh</button></div>
 <table id="credTable" hidden>
  <thead><tr><th>Email</th><th>Credential ID</th><th>Status</th><th>Last used</th><th></th></tr></thead>
  <tbody id="credRows"></tbody>
 </table>
 <p id="credMsg" class="meta"></p>
</section>

<section id="panelIps" role="tabpanel" aria-labelledby="tabIps" hidden>
 <h2>Authorized IPs</h2>
 <label for="ipSearch">Search</label>
 <input id="ipSearch" type="search" placeholder="IP address or email" autocomplete="off">
 <div class="meta"><span id="ipCount">Loading...</span><button id="ipRefresh" class="act">Refresh</button></div>
 <table id="ipTable" hidden>
  <thead><tr><th>Source IP</th><th>Authenticated key</th><th></th></tr></thead>
  <tbody id="ipRows"></tbody>
 </table>
 <p id="ipMsg" class="meta"></p>
</section>

<div id="status"></div>

<footer><a href="/">Back to the authenticate page</a></footer>

<script nonce="__CSP_NONCE__">
const $ = (id) => document.getElementById(id);

function b64urlToBuf(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  s += '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u.buffer;
}

function bufToB64url(buf) {
  const u = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function request(url, method, payload) {
  const init = { method: method, headers: { 'Content-Type': 'application/json' } };
  if (payload !== undefined) {
    init.body = JSON.stringify(payload);
  }
  const r = await fetch(url, init);
  let j = null;
  try { j = await r.json(); } catch (e) {}
  if (!r.ok) {
    throw new Error(url + ': HTTP ' + r.status + (j && j.error ? ' (' + j.error + ')' : ''));
  }
  return j;
}
const postJson = (url, payload) => request(url, 'POST', payload);
const getJson = (url) => request(url, 'GET');

const HINTS = {
  invalid_email: 'not a usable email address - check for a typo, a stray space or a missing domain',
  busy: 'no free ceremony slot (kMaxSessions) - retry shortly',
  rate_limited: 'this IP is over its connection budget - retry shortly'
};
function explain(e) {
  for (const code in HINTS) {
    if (e.message.indexOf(code) >= 0) { return e.message + ' - ' + HINTS[code]; }
  }
  return e.message;
}

let creds = [];
let ips = [];
let credsLoaded = false;
let ipsLoaded = false;
let enrolling = false;
let credSort = 'newest';

function setStatus(msg, isError) {
  $('status').textContent = msg;
  $('status').className = isError ? 'err' : '';
}

const TABS = ['Enroll', 'Creds', 'Ips'];
const HASH = { Enroll: 'enroll', Creds: 'registered', Ips: 'ips' };

function selectTab(name, focus) {
  for (const t of TABS) {
    const on = (t === name);
    $('tab' + t).setAttribute('aria-selected', on ? 'true' : 'false');
    $('panel' + t).hidden = !on;
  }
  if (focus) { $('tab' + name).focus(); }
  if (name === 'Creds' && !credsLoaded) { loadCreds(); }
  if (name === 'Ips' && !ipsLoaded) { loadIps(); }
  if (location.hash !== '#' + HASH[name]) { history.replaceState(null, '', '#' + HASH[name]); }
}

function revokeControl(onConfirm) {
  const wrap = document.createElement('span');
  wrap.className = 'pop';

  const ask = document.createElement('button');
  ask.type = 'button';
  ask.className = 'act';
  ask.textContent = 'Revoke';

  const panel = document.createElement('span');
  panel.className = 'panel';

  const warn = document.createElement('span');
  warn.className = 'confirm';
  warn.textContent = 'Revoke permanently?';

  const yes = document.createElement('button');
  yes.type = 'button';
  yes.className = 'act';
  yes.textContent = 'Yes, revoke';

  const no = document.createElement('button');
  no.type = 'button';
  no.className = 'act';
  no.textContent = 'Cancel';

  panel.append(warn, yes, no);
  wrap.append(ask, panel);

  function close() {
    panel.classList.remove('open');
    document.removeEventListener('click', onDocClick);
    document.removeEventListener('keydown', onKey);
  }
  function open() {
    panel.classList.add('open');
    document.addEventListener('click', onDocClick);
    document.addEventListener('keydown', onKey);
  }
  function onDocClick(e) {
    if (!wrap.contains(e.target)) close();
  }
  function onKey(e) {
    if (e.key === 'Escape') close();
  }

  ask.addEventListener('click', (e) => {
    e.stopPropagation();
    panel.classList.contains('open') ? close() : open();
  });
  no.addEventListener('click', () => close());
  yes.addEventListener('click', () => { close(); onConfirm(); });

  return wrap;
}

function formatWhen(unix) {
  const d = new Date(unix * 1000);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function lastUsedCell(c) {
  const cell = document.createElement('td');
  if (c.lastSeenUnix > 0) {
    const when = document.createElement('span');
    when.className = 'when';
    when.textContent = formatWhen(c.lastSeenUnix);
    when.title = 'last authenticated at this time (device clock, NTP-synced)';
    cell.appendChild(when);
    return cell;
  }
  const mark = document.createElement('span');
  if (c.usedThisBoot === true) {
    mark.className = 'dot';
    mark.textContent = '\u25CF';
    mark.title = 'used since this boot, no date recorded';
  } else if (c.usedThisBoot === false) {
    mark.className = 'dash';
    mark.textContent = '\u2014';
    mark.title = 'not used since this boot';
  } else {
    mark.className = 'dash';
    mark.textContent = '?';
    mark.title = 'unknown (the store is not tracking this)';
  }
  cell.appendChild(mark);
  return cell;
}

function stateCell(c) {
  const cell = document.createElement('td');
  const text = document.createElement('span');
  text.className = c.disabled ? 'state off' : 'state';
  text.textContent = c.disabled ? 'Disabled' : 'Active';
  cell.appendChild(text);
  return cell;
}

function sortCreds(list) {
  return list.slice().sort((a, b) => {
    const av = a.lastSeenUnix || 0;
    const bv = b.lastSeenUnix || 0;
    if (av === 0 && bv === 0) { return 0; }
    if (av === 0) { return 1; }
    if (bv === 0) { return -1; }
    return credSort === 'newest' ? bv - av : av - bv;
  });
}

function renderCreds() {
  const typed = $('credSearch').value.trim();
  const q = typed.toLowerCase();
  const matched = q ? creds.filter((c) => c.email.toLowerCase().indexOf(q) >= 0 ||
                                        String(c.id).toLowerCase().indexOf(q) >= 0) : creds;
  const shown = sortCreds(matched);
  const body = $('credRows');
  body.textContent = '';
  for (const c of shown) {
    const tr = document.createElement('tr');
    const email = document.createElement('td');
    email.textContent = c.email;
    const id = document.createElement('td');
    id.className = 'id';
    id.textContent = String(c.id).slice(0, 10) + '...';
    id.title = c.id;
    const act = document.createElement('td');
    act.className = 'act';
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'act';
    toggle.textContent = c.disabled ? 'Enable' : 'Disable';
    toggle.title = c.disabled ? 'let this key authenticate again'
                              : 'block this key without deleting it';
    toggle.addEventListener('click', () => setDisabled(c.id, !c.disabled));
    act.appendChild(toggle);
    act.appendChild(revokeControl(() => revokeCred(c.id)));
    tr.append(email, id, stateCell(c), lastUsedCell(c), act);
    body.appendChild(tr);
  }
  $('credTable').hidden = (shown.length === 0);
  const disabled = creds.filter((c) => c.disabled).length;
  let count = creds.length === 0 ? 'No keys enrolled'
    : (q ? shown.length + ' of ' + creds.length + ' shown'
         : creds.length + (creds.length === 1 ? ' key' : ' keys'));
  if (disabled > 0) { count += ' (' + disabled + ' disabled)'; }
  $('credCount').textContent = count;
  $('credMsg').textContent = shown.length > 0 ? ''
    : (creds.length === 0 ? 'Nothing enrolled yet - use the Enroll Key tab to add a key.'
                          : 'No key matches "' + typed + '".');
}

function renderIps() {
  const typed = $('ipSearch').value.trim();
  const q = typed.toLowerCase();
  const me = ($('ip').textContent || '').trim();
  const matches = (e) => e.ip.toLowerCase().indexOf(q) >= 0 ||
    (e.users || []).some((u) => u.toLowerCase().indexOf(q) >= 0);
  const shown = q ? ips.filter(matches) : ips;
  const body = $('ipRows');
  body.textContent = '';
  for (const entry of shown) {
    const tr = document.createElement('tr');
    const addr = document.createElement('td');
    addr.textContent = entry.ip;
    if (entry.ip === me) {
      const you = document.createElement('span');
      you.className = 'you';
      you.textContent = ' (this admin host)';
      addr.appendChild(you);
    }
    const who = document.createElement('td');
    who.className = 'who';
    who.textContent = (entry.users || []).length ? entry.users.join(', ') : '-';
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'act';
    btn.textContent = 'Revoke';
    btn.addEventListener('click', () => revokeIp(entry.ip, btn));
    const act = document.createElement('td');
    act.className = 'act';
    act.appendChild(btn);
    tr.append(addr, who, act);
    body.appendChild(tr);
  }
  $('ipTable').hidden = (shown.length === 0);
  $('ipCount').textContent = ips.length === 0 ? 'No IPs authorized'
    : (q ? shown.length + ' of ' + ips.length + ' shown'
         : ips.length + (ips.length === 1 ? ' IP' : ' IPs'));
  $('ipMsg').textContent = shown.length > 0 ? ''
    : (ips.length === 0 ? 'No IP is currently authorized - an IP is added by a successful authentication from it.'
                        : 'No IP matches "' + typed + '".');
}

async function enroll() {
  if (enrolling) return;
  enrolling = true;
  const email = $('email').value.trim();
  if (!email) { setStatus('Enter an email address first.', true); enrolling = false; return; }
  setStatus('Enrolling...', false);
  try {
    const opts = await postJson('/register/start', { email: email });
    opts.challenge = b64urlToBuf(opts.challenge);
    opts.user.id = b64urlToBuf(opts.user.id);

    const cred = await navigator.credentials.create({ publicKey: opts });

    const body = {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        attestationObject: bufToB64url(cred.response.attestationObject)
      }
    };
    await postJson('/register/finish', body);
    setStatus('Enrolled ' + email + '.', false);
    credsLoaded = false;
    selectTab('Creds', false);
  } catch (e) {
    setStatus('Error: ' + explain(e), true);
  } finally {
    enrolling = false;
  }
}

async function loadCreds() {
  try {
    creds = await getJson('/admin/credentials');
    credsLoaded = true;
    $('tabCreds').textContent = 'Registered Keys (' + creds.length + ')';
    renderCreds();
  } catch (e) {
    credsLoaded = false;
    setStatus('Error: ' + explain(e), true);
  }
}

async function loadIps() {
  try {
    ips = await getJson('/admin/authorized-ips');
    ipsLoaded = true;
    $('tabIps').textContent = 'Authorized IPs (' + ips.length + ')';
    renderIps();
  } catch (e) {
    ipsLoaded = false;
    setStatus('Error: ' + explain(e), true);
  }
}

async function reloadAfterKeyChange() {
  await loadCreds();
  if (ipsLoaded) { await loadIps(); }
}

async function revokeCred(id) {
  setStatus('Revoking key...', false);
  try {
    await postJson('/admin/revoke-credential', { id: id });
    setStatus('Key revoked. It cannot authenticate again until it is enrolled once more.', false);
    await reloadAfterKeyChange();
  } catch (e) {
    setStatus('Error: ' + explain(e), true);
  }
}

async function revokeIp(ip, btn) {
  btn.disabled = true;
  setStatus('Revoking ' + ip + '...', false);
  try {
    await postJson('/admin/revoke-ip', { ip: ip });
    setStatus('Revoked ' + ip + '.', false);
    await loadIps();
  } catch (e) {
    btn.disabled = false;
    setStatus('Error: ' + explain(e), true);
  }
}

async function setDisabled(id, disabled) {
  setStatus(disabled ? 'Disabling the key...' : 'Enabling the key...', false);
  try {
    await postJson('/admin/set-credential-disabled', { id: id, disabled: disabled });
    setStatus(disabled ? 'Key disabled, device record retained.'
                       : 'Key re-enabled.', false);
    await reloadAfterKeyChange();
  } catch (e) {
    setStatus('Error: ' + explain(e), true);
  }
}

$('regBtn').addEventListener('click', enroll);
$('credRefresh').addEventListener('click', loadCreds);
$('ipRefresh').addEventListener('click', loadIps);
$('credSearch').addEventListener('input', renderCreds);
$('ipSearch').addEventListener('input', renderIps);
$('credSortBtn').addEventListener('click', () => {
  credSort = (credSort === 'newest') ? 'oldest' : 'newest';
  $('credSortBtn').textContent = 'Sort: ' + (credSort === 'newest' ? 'newest first' : 'dormant first');
  renderCreds();
});
for (const [i, t] of TABS.entries()) {
  $('tab' + t).addEventListener('click', () => selectTab(t, false));
  $('tab' + t).addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') { return; }
    const step = e.key === 'ArrowRight' ? 1 : TABS.length - 1;
    selectTab(TABS[(i + step) % TABS.length], true);
  });
}

const fromHash = (location.hash || '').replace('#', '').toLowerCase();
selectTab(fromHash === 'registered' ? 'Creds' : (fromHash === 'ips' ? 'Ips' : 'Enroll'), false);
</script>
</body>
</html>
)RAW";

#endif // ADMINHTML_H