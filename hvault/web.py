"""Minimal local web console over the tool registry (standard library only).

Binds to the loopback interface and guards every request with a random key, so
only someone on this machine who was given the printed URL can drive it. Tools
run through the same runner as the CLI - argv is a list, never a shell string.
This console runs tools on your box: keep it local, do not expose the port.
"""

import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import runner

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>hacking-vault</title>
<style>
:root{--bg:#05080a;--panel:#0b1016;--panel2:#0e141b;--border:#1b2a22;
--fg:#c8f7d8;--mut:#5f7d6b;--acc:#2ee66b;--acc2:#19c2ff;--ok:#2ee66b;
--warn:#f5c451;--err:#ff5f56}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;height:100vh;overflow:hidden;display:flex;flex-direction:column;
font:14px/1.55 "JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
background:
  radial-gradient(1200px 600px at 80% -10%,#0c1f16 0%,transparent 60%),
  var(--bg);
color:var(--fg)}
::selection{background:var(--acc);color:#02130a}
/* scrollbars */
*{scrollbar-width:thin;scrollbar-color:#1f3a2a transparent}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-thumb{background:#1f3a2a;border-radius:6px;border:2px solid transparent;
background-clip:content-box}
::-webkit-scrollbar-thumb:hover{background:#2e5a40;background-clip:content-box}

header{flex:0 0 auto;display:flex;align-items:center;gap:14px;
padding:12px 20px;border-bottom:1px solid var(--border);
background:linear-gradient(180deg,#0a130d,#060a07)}
.dots{display:flex;gap:7px}.dots i{width:11px;height:11px;border-radius:50%;display:block}
.dots i:nth-child(1){background:var(--err)}.dots i:nth-child(2){background:var(--warn)}
.dots i:nth-child(3){background:var(--ok)}
header h1{margin:0;font-size:15px;color:var(--acc);letter-spacing:.5px;
text-shadow:0 0 10px #2ee66b66;font-weight:700}
header h1 .host{color:var(--fg)}header h1 .path{color:var(--acc2)}
.cursor{display:inline-block;width:8px;height:15px;background:var(--acc);
margin-left:2px;vertical-align:-2px;animation:blink 1.1s steps(1) infinite;
box-shadow:0 0 8px #2ee66b}
@keyframes blink{50%{opacity:0}}
header .meta{margin-left:auto;color:var(--mut);font-size:12px;text-align:right}
header .meta b{color:var(--acc)}

.wrap{flex:1 1 auto;display:flex;min-height:0}
aside{flex:0 0 288px;display:flex;flex-direction:column;min-height:0;
border-right:1px solid var(--border);background:linear-gradient(180deg,#070c09,#050807)}
.search{flex:0 0 auto;padding:12px;border-bottom:1px solid var(--border)}
.search input{width:100%;padding:9px 11px 9px 30px;background:var(--panel);
border:1px solid var(--border);border-radius:7px;color:var(--fg);font:inherit;
background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' fill='none' stroke='%235f7d6b' stroke-width='2' viewBox='0 0 24 24'%3E%3Ccircle cx='11' cy='11' r='7'/%3E%3Cpath d='m21 21-4.3-4.3'/%3E%3C/svg%3E");
background-repeat:no-repeat;background-position:10px center}
.search input:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 2px #2ee66b22}
.list{flex:1 1 auto;overflow-y:auto;min-height:0;padding:8px 10px 20px}
.cat{margin-top:14px}.cat:first-child{margin-top:4px}
.cat>h3{position:sticky;top:0;z-index:1;margin:0 0 6px;padding:5px 4px;
color:var(--acc);font-size:10px;letter-spacing:1.5px;text-transform:uppercase;
background:linear-gradient(180deg,#070c09,#070c09ee);display:flex;gap:8px;align-items:center}
.cat>h3::before{content:">";color:var(--mut)}
.cat>h3 .n{margin-left:auto;color:var(--mut);letter-spacing:0}
.tool{padding:8px 10px;border-radius:7px;cursor:pointer;margin-bottom:3px;
border:1px solid transparent;transition:background .08s,border-color .08s}
.tool:hover{background:var(--panel)}
.tool.active{background:#0f2417;border-color:var(--acc);
box-shadow:inset 2px 0 0 var(--acc),0 0 14px #2ee66b22}
.tool b{display:block;color:var(--fg);font-weight:600}
.tool.active b{color:var(--acc)}
.tool small{color:var(--mut);display:block;white-space:nowrap;overflow:hidden;
text-overflow:ellipsis}
.empty-hint{color:var(--mut);padding:16px 8px;font-size:12px;display:none}

main{flex:1 1 auto;overflow-y:auto;min-height:0;min-width:0;padding:22px}
.welcome{color:var(--mut);max-width:560px}
.welcome pre{background:none;border:0;color:var(--acc);text-shadow:0 0 8px #2ee66b44;
padding:0;margin:0 0 14px;font-size:12px;line-height:1.3}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;
padding:18px;margin-bottom:16px;box-shadow:0 1px 0 #00000040}
.card h2{margin:0 0 4px;font-size:16px;color:var(--acc);text-shadow:0 0 8px #2ee66b33}
label{display:block;margin:12px 0 4px;color:var(--mut);font-size:12px}
input[type=text],select,textarea{width:100%;padding:9px 11px;background:#04070a;
border:1px solid var(--border);border-radius:7px;color:var(--fg);font:inherit}
input[type=text]:focus,select:focus,textarea:focus{outline:none;border-color:var(--acc);
box-shadow:0 0 0 2px #2ee66b22}
textarea{min-height:76px;resize:vertical}
.chk{display:flex;align-items:center;gap:9px;margin:10px 0}
.chk input{width:16px;height:16px;accent-color:var(--acc)}
.chk label{margin:0}
button.run{background:var(--acc);color:#02130a;border:0;padding:10px 22px;
border-radius:7px;font:inherit;font-weight:700;cursor:pointer;margin-top:16px;
letter-spacing:.3px;box-shadow:0 0 14px #2ee66b55}
button.run:hover{filter:brightness(1.08)}
button.run:disabled{opacity:.55;cursor:wait;box-shadow:none}
.cmd{color:var(--acc2);margin:12px 0 0;word-break:break-all;font-size:12px}
.cmd::before{content:"$ ";color:var(--mut)}
.out-head{display:flex;align-items:center;gap:10px;margin-bottom:8px;color:var(--mut);
font-size:12px}
.pill{font-size:11px;padding:1px 9px;border-radius:10px;border:1px solid var(--border)}
.pill.ok{color:var(--ok);border-color:#1f5a35}.pill.bad{color:var(--err);border-color:#5a2420}
pre.out{background:#02050a;border:1px solid var(--border);border-radius:8px;padding:14px;
white-space:pre-wrap;word-break:break-word;max-height:58vh;overflow:auto;margin:0;
color:var(--fg)}
.note{color:var(--warn);font-size:12px;margin-top:8px}.muted{color:var(--mut)}
.badge{font-size:11px;color:var(--mut);border:1px solid var(--border);border-radius:10px;
padding:1px 9px;margin-left:8px;vertical-align:middle}
</style></head><body>
<header>
  <span class="dots"><i></i><i></i><i></i></span>
  <h1>root@<span class="host">hacking-vault</span>:<span class="path">~</span># <span class="cursor"></span></h1>
  <div class="meta"><b id="count">0</b> tools loaded · loopback + key · authorized use only</div>
</header>
<div class="wrap">
  <aside>
    <div class="search"><input id="q" type="text" autocomplete="off" spellcheck="false"
      placeholder="filter tools... (/)"></div>
    <div class="list" id="list"><div class="empty-hint" id="nohit">no tool matches that filter.</div></div>
  </aside>
  <main id="main">
    <div class="welcome">
      <pre>  _                _    _                            _ _
 | |__   __ _  ___| | _(_)_ __   __ _  __   ____ _ _   _| | |_
 | '_ \ / _` |/ __| |/ / | '_ \ / _` | \ \ / / _` | | | | | __|
 | | | | (_| | (__|   <| | | | | (_| |  \ V / (_| | |_| | | |_
 |_| |_|\__,_|\___|_|\_\_|_| |_|\__, |   \_/ \__,_|\__,_|_|\__|
                                |___/</pre>
      Pick a tool on the left, or hit <b>/</b> to filter. Each run executes locally
      and streams its output below. Authorized / educational use only.
    </div>
  </main>
</div>
<script id="cfg" type="application/json">__CONFIG__</script>
<script>
const CFG=JSON.parse(document.getElementById('cfg').textContent);
const AUTH=CFG.auth, TOOLS=CFG.tools;
const list=document.getElementById('list'), main=document.getElementById('main');
const nohit=document.getElementById('nohit');
document.getElementById('count').textContent=TOOLS.length;
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>(
  {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

const cats={};
TOOLS.forEach(t=>(cats[t.category]=cats[t.category]||[]).push(t));
const els=[];  // {tool, el, cat}
for(const c in cats){
  const sec=document.createElement('div');sec.className='cat';
  const h=document.createElement('h3');
  h.innerHTML=esc(c)+'<span class="n">'+cats[c].length+'</span>';
  sec.appendChild(h);
  cats[c].forEach(t=>{
    const d=document.createElement('div');d.className='tool';
    d.innerHTML='<b>'+esc(t.name)+'</b><small>'+esc(t.summary)+'</small>';
    d.onclick=()=>select(t,d);
    sec.appendChild(d);els.push({tool:t,el:d,cat:sec});
  });
  list.appendChild(sec);
}

function select(t,el){
  els.forEach(x=>x.el.classList.remove('active'));
  el.classList.add('active');render(t);
}

function filter(q){
  q=q.trim().toLowerCase();
  const live=new Set();let any=false;
  els.forEach(x=>{
    const t=x.tool;
    const hit=!q||(t.name+' '+t.summary+' '+t.id+' '+t.category).toLowerCase().includes(q);
    x.el.style.display=hit?'':'none';
    if(hit){live.add(x.cat);any=true;}
  });
  document.querySelectorAll('.cat').forEach(s=>s.style.display=live.has(s)?'':'none');
  nohit.style.display=any?'none':'block';
}
const q=document.getElementById('q');
q.addEventListener('input',()=>filter(q.value));
document.addEventListener('keydown',e=>{
  if(e.key==='/'&&document.activeElement!==q){e.preventDefault();q.focus();}
  if(e.key==='Escape'&&document.activeElement===q){q.value='';filter('');q.blur();}
});

function field(p){
  const id='p_'+p.key, req=p.required?' <span style="color:var(--acc)">*</span>':'';
  if(p.kind==='flag')
    return '<div class="chk"><input type="checkbox" id="'+id+'">'+
           '<label for="'+id+'">'+esc(p.label)+'</label></div>';
  if(p.kind==='choice')
    return '<label>'+esc(p.label)+req+'</label><select id="'+id+'">'+
      p.choices.map(c=>'<option value="'+esc(c)+'">'+esc(c||'(none)')+'</option>').join('')+
      '</select>';
  if(p.kind==='text')
    return '<label>'+esc(p.label)+req+'</label><textarea id="'+id+'"></textarea>';
  return '<label>'+esc(p.label)+req+'</label><input type="text" id="'+id+
         '" value="'+esc(p.default)+'">';
}

function render(t){
  let f='<div class="card"><h2>'+esc(t.name)+
    '<span class="badge">'+esc(t.category)+'</span></h2>'+
    '<div class="muted">'+esc(t.summary)+'</div>';
  if(t.note)f+='<div class="note">'+esc(t.note)+'</div>';
  f+='<form id="f">'+t.params.map(field).join('')+
    '<button type="submit" class="run">▶ Run</button></form>'+
    '<div class="cmd" id="cmd" style="display:none"></div></div>'+
    '<div class="card"><div class="out-head">output'+
    '<span class="pill" id="pill" style="display:none"></span></div>'+
    '<pre class="out muted" id="out">(no output yet)</pre></div>';
  main.innerHTML=f;
  document.getElementById('f').onsubmit=e=>{e.preventDefault();runTool(t);};
}

async function runTool(t){
  const values={};
  t.params.forEach(p=>{
    const el=document.getElementById('p_'+p.key);
    values[p.key]=p.kind==='flag'?el.checked:el.value;
  });
  const btn=document.querySelector('button.run');
  btn.disabled=true;btn.textContent='running...';
  const out=document.getElementById('out');out.textContent='running...';out.className='out';
  const pill=document.getElementById('pill');pill.style.display='none';
  try{
    const r=await fetch('/api/run?k='+AUTH,{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({id:t.id,values})});
    const d=await r.json();
    const cmd=document.getElementById('cmd');
    cmd.style.display='block';cmd.textContent=d.cmd;
    out.textContent=d.output||'(no output)';
    pill.style.display='inline-block';
    pill.textContent='exit '+d.rc;pill.className='pill '+(d.rc===0?'ok':'bad');
  }catch(err){out.textContent='request failed: '+err;}
  btn.disabled=false;btn.textContent='▶ Run';
}
</script></body></html>"""


def _tools_data(registry):
    data = []
    for spec in registry:
        data.append({
            "id": spec.id, "category": spec.category, "name": spec.name,
            "summary": spec.summary, "note": spec.note,
            "params": [{"key": p.key, "label": p.label, "required": p.required,
                        "default": p.default, "kind": p.kind,
                        "choices": list(p.choices)} for p in spec.params],
        })
    return data


def make_handler(registry, auth, timeout):
    specs = {s.id: s for s in registry}
    tools = _tools_data(registry)
    config = json.dumps({"auth": auth, "tools": tools})
    page = PAGE.replace("__CONFIG__", config)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _host_ok(self):
            host = (self.headers.get("Host") or "").split(":")[0]
            return host in ("127.0.0.1", "localhost", "[::1]", "")

        def _auth_ok(self):
            q = parse_qs(urlparse(self.path).query)
            return secrets.compare_digest(q.get("k", [""])[0], auth)

        def _send(self, code, body, ctype="application/json"):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, "forbidden", "text/plain")
            route = urlparse(self.path).path
            if route == "/":
                return self._send(200, page, "text/html; charset=utf-8")
            if route == "/api/tools" and self._auth_ok():
                return self._send(200, json.dumps(tools))
            self._send(404, "not found", "text/plain")

        def do_POST(self):
            if not self._host_ok() or not self._auth_ok():
                return self._send(403, '{"error":"forbidden"}')
            if urlparse(self.path).path != "/api/run":
                return self._send(404, '{"error":"not found"}')
            length = int(self.headers.get("Content-Length", 0))
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._send(400, '{"error":"bad json"}')
            spec = specs.get(payload.get("id"))
            if not spec:
                return self._send(404, '{"error":"unknown tool"}')
            values = payload.get("values", {})
            rc, out = runner.run(spec, values, timeout=timeout)
            self._send(200, json.dumps({
                "rc": rc, "output": out,
                "cmd": runner.preview_cmd(spec, values)}))

    return Handler


def serve(registry, host="127.0.0.1", port=0, open_browser=True, timeout=300):
    auth = secrets.token_urlsafe(16)
    handler = make_handler(registry, auth, timeout)
    httpd = ThreadingHTTPServer((host, port), handler)
    real_port = httpd.server_address[1]
    url = f"http://{host}:{real_port}/?k={auth}"
    print(f"[+] hacking-vault web console on {url}")
    print("    Loopback + key only. Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] stopped.")
        httpd.shutdown()
