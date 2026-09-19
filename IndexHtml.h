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
<style nonce="__CSP_NONCE__">body{font-family:system-ui,sans-serif;max-width:640px;margin:2em auto;padding:0 1em;color:#222}h1{font-size:1.4em}h2{font-size:1.15em;margin-top:1.5em}button{padding:.5em 1em;margin:.25em .5em .25em 0;cursor:pointer}#res{margin-top:1em;white-space:pre-wrap}#reauth{display:none;background:#fff3cd;border:1px solid #ffc107;padding:.75em;margin:1em 0}#reauth button{background:#ffc107;border:none;color:#222}</style>
</head>
<body>
<h1>PoE-Passkey</h1>
<p>Your IP: <strong id="ip">__CLIENT_IP__</strong></p>
<div id="reauth">
  Your IP has changed since your last authorization.
  <button id="reauthBtn">Tap to re-authorize</button>
</div>
<h2>Authenticate</h2>
<p>Plug in your security key and click "Authenticate with security key" to authorize your IP address.</p>
<button id="authBtn">Authenticate with security key</button>
<div id="res"></div>

<script nonce="__CSP_NONCE__">
const $=id=>document.getElementById(id);function b64urlToBuf(s){s=s.replace(/-/g,'+').replace(/_/g,'/');s+='='.repeat((4-s.length%4)%4);return Uint8Array.from(atob(s),c=>c.charCodeAt(0)).buffer}function bufToB64url(b){return btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}async function request(u,m,p){const i={method:m,headers:{'Content-Type':'application/json'}};if(p!==undefined)i.body=JSON.stringify(p);const r=await fetch(u,i);let j=null;try{j=await r.json()}catch(e){}if(!r.ok)throw new Error(u+': HTTP '+r.status+(j&&j.error?' ('+j.error+')':''));return j}function noteIp(ip){$('ip').textContent=ip;const l=localStorage.getItem('lastIp');if(l&&l!==ip)$('reauth').style.display='block';else if(!l)localStorage.setItem('lastIp',ip)}async function pollIp(){try{const j=await(await fetch('/whoami')).json();if(j.ip)noteIp(j.ip)}catch(e){}}let authBusy=false;async function authenticate(){if(authBusy)return;authBusy=true;$('res').textContent='Requesting challenge...';try{const o=await request('/auth/start','POST');o.challenge=b64urlToBuf(o.challenge);let c;try{c=await navigator.credentials.get({publicKey:o})}catch(e){await fetch('/auth/cancel',{method:'POST',headers:{'Content-Type':'application/json'}}).catch(()=>{});throw e}const f=bufToB64url;const b={id:c.id,rawId:f(c.rawId),response:{clientDataJSON:f(c.response.clientDataJSON),authenticatorData:f(c.response.authenticatorData),signature:f(c.response.signature),userHandle:c.response.userHandle?f(c.response.userHandle):null}};await request('/auth/finish','POST',b);localStorage.setItem('lastIp',$('ip').textContent);$('reauth').style.display='none';$('res').textContent='Authenticated.'}catch(e){$('res').textContent='Error: '+e.message}finally{authBusy=false}}$('authBtn').addEventListener('click',authenticate);$('reauthBtn').addEventListener('click',authenticate);const p=$('ip').textContent.trim();p&&!p.startsWith('__')?noteIp(p):pollIp();setInterval(()=>{document.hidden||pollIp()},60000);

</script>
</body>
</html>
)RAW";

#endif // INDEXHTML_H