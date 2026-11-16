/*
 * IndexHtml.h
 *
 * The PUBLIC page served at GET / for the WebAuthn authentication flow
 *
 */

#ifndef INDEXHTML_H
#define INDEXHTML_H

static const char kIndexHtml[] = R"RAW(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PoE-Passkey</title>
<link rel="icon" href="data:,">
<style nonce="__CSP_NONCE__">body{font-family:system-ui,sans-serif;max-width:640px;margin:2em auto;padding:0 1em;color:#222}h1{font-size:1.4em}h2{font-size:1.15em;margin-top:1.5em}button{padding:.5em 1em;margin:.25em .5em .25em 0;cursor:pointer}#res{margin-top:1em;white-space:pre-wrap}#reauth{display:none;background:#fff3cd;border:1px solid #ffc107;padding:.75em;margin:1em 0}#reauth button{background:#ffc107;border:none;color:#222}#ok{margin-top:1em;padding:1em 1.25em;border:2px solid #1b5e20;border-left-width:.5em;background:#e8f5e9;border-radius:6px}#ok h2{margin:.2em 0 .4em;color:#1b5e20;font-size:1.5em}#res.ok,#res.err{padding:.5em .75em;border-radius:4px}#res.ok{background:#e8f5e9}#res.err{background:#ffebee}</style>
</head>
<body>
<h1>PoE-Passkey</h1>
<p>Your IP: <strong id="ip">__CLIENT_IP__</strong></p>
<div id="reauth">
  Your IP has changed since your last authorization.
  <button id="reauthBtn">Tap to re-authorize</button>
</div>
<div id="authBox">
<h2>Authenticate</h2>
<p>Plug in your security key and click "Authenticate with security key" to authorize your IP address.</p>
<button id="authBtn">Authenticate with security key</button>
</div>
<div id="res"></div>
<div id="ok" role="status" aria-live="polite" hidden>
<h2>Successfully Authenticated</h2>
<p>Your IP address <strong id="okIp"></strong> is authorized.</p>
</div>

<script nonce="__CSP_NONCE__">
const $=id=>document.getElementById(id);function b64urlToBuf(s){s=s.replace(/-/g,'+').replace(/_/g,'/');s+='='.repeat((4-s.length%4)%4);return Uint8Array.from(atob(s),c=>c.charCodeAt(0)).buffer}function bufToB64url(b){return btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}async function request(u,m,p){const i={method:m,headers:{'Content-Type':'application/json'}};if(p!==undefined)i.body=JSON.stringify(p);const r=await fetch(u,i);let j=null;try{j=await r.json()}catch(e){}if(!r.ok)throw new Error(u+': HTTP '+r.status+(j&&j.error?' ('+j.error+')':''));return j}function noteIp(ip){$('ip').textContent=ip;const l=localStorage.getItem('lastIp');if(l&&l!==ip){hideOk();$('reauth').style.display='block'}else if(!l)localStorage.setItem('lastIp',ip)}async function pollIp(){try{const j=await(await fetch('/whoami')).json();if(j.ip)noteIp(j.ip)}catch(e){}}const OK_MS=30000;let okTimer=0;function showOk(){$('okIp').textContent=$('ip').textContent.trim();$('authBox').hidden=true;$('ok').hidden=false;$('reauth').style.display='none';$('res').textContent='';$('res').className='';document.title='Successfully Authenticated - PoE-Passkey';clearTimeout(okTimer);okTimer=setTimeout(function(){$('ok').hidden=true;$('authBox').hidden=false;$('res').textContent='Successfully Authenticated';$('res').className='ok'},OK_MS)}function hideOk(){clearTimeout(okTimer);$('ok').hidden=true;$('authBox').hidden=false;$('res').textContent='';$('res').className=''}let authBusy=false;async function authenticate(){if(authBusy)return;authBusy=true;hideOk();document.title='PoE-Passkey';$('res').textContent='Requesting challenge...';$('res').className='';try{const o=await request('/auth/start','POST');o.challenge=b64urlToBuf(o.challenge);let c;try{c=await navigator.credentials.get({publicKey:o})}catch(e){await fetch('/auth/cancel',{method:'POST',headers:{'Content-Type':'application/json'}}).catch(()=>{});throw e}const f=bufToB64url;const b={id:c.id,rawId:f(c.rawId),response:{clientDataJSON:f(c.response.clientDataJSON),authenticatorData:f(c.response.authenticatorData),signature:f(c.response.signature),userHandle:c.response.userHandle?f(c.response.userHandle):null}};await request('/auth/finish','POST',b);localStorage.setItem('lastIp',$('ip').textContent);showOk()}catch(e){hideOk();document.title='PoE-Passkey';if(e.name==='NotAllowedError'||e.name==='NotSupportedError'){$('res').textContent='Authentication failed or timed out.'}else{$('res').textContent=e.message.indexOf('authorized_ip_store_full')>=0?'No free authorization slots. Contact an administrator.':'Error: '+e.message}$('res').className='err'}finally{authBusy=false}}$('authBtn').addEventListener('click',authenticate);$('reauthBtn').addEventListener('click',authenticate);const p=$('ip').textContent.trim();p&&!p.startsWith('__')?noteIp(p):pollIp();setInterval(()=>{document.hidden||pollIp()},60000);

</script>
</body>
</html>
)RAW";

#endif // INDEXHTML_H