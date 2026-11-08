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
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--mut:#8b949e;
--acc:#2f81f7;--ok:#3fb950;--warn:#d29922}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 ui-monospace,SFMono-Regular,
Menlo,Consolas,monospace;background:var(--bg);color:var(--fg)}
header{padding:14px 20px;border-bottom:1px solid var(--border);display:flex;
align-items:baseline;gap:12px}header h1{margin:0;font-size:18px}
header span{color:var(--mut);font-size:12px}
.wrap{display:flex;min-height:calc(100vh - 52px)}
aside{width:260px;border-right:1px solid var(--border);padding:12px;overflow:auto}
aside h3{color:var(--mut);font-size:11px;text-transform:uppercase;margin:14px 0 6px}
.tool{padding:7px 9px;border-radius:6px;cursor:pointer;margin-bottom:2px}
.tool:hover{background:var(--panel)}.tool.active{background:#1f6feb33;
outline:1px solid var(--acc)}.tool b{display:block}.tool small{color:var(--mut)}
main{flex:1;padding:20px;overflow:auto}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;
padding:16px;margin-bottom:16px}
label{display:block;margin:10px 0 3px;color:var(--mut)}
input[type=text],select{width:100%;padding:8px;background:var(--bg);
border:1px solid var(--border);border-radius:6px;color:var(--fg);font:inherit}
textarea{width:100%;min-height:70px;padding:8px;background:var(--bg);
border:1px solid var(--border);border-radius:6px;color:var(--fg);font:inherit}
.chk{display:flex;align-items:center;gap:8px;margin:8px 0}
.chk input{width:16px;height:16px}
button{background:var(--acc);color:#fff;border:0;padding:10px 18px;border-radius:6px;
font:inherit;cursor:pointer;margin-top:12px}button:disabled{opacity:.5;cursor:wait}
.cmd{color:var(--mut);margin:10px 0;word-break:break-all}
pre{background:#010409;border:1px solid var(--border);border-radius:6px;padding:12px;
white-space:pre-wrap;word-break:break-word;max-height:55vh;overflow:auto;margin:0}
.note{color:var(--warn);font-size:12px;margin-top:8px}.muted{color:var(--mut)}
.badge{font-size:11px;color:var(--mut);border:1px solid var(--border);border-radius:10px;
padding:1px 8px;margin-left:6px}
</style></head><body>
<header><h1>hacking-vault</h1><span>local console - authorized use only</span></header>
<div class="wrap">
<aside id="side"></aside>
<main id="main"><div class="card muted">Select a tool on the left.</div></main>
</div>
<script id="cfg" type="application/json">__CONFIG__</script>
<script>
const CFG=JSON.parse(document.getElementById('cfg').textContent);
const AUTH=CFG.auth, TOOLS=CFG.tools;
const side=document.getElementById('side'), main=document.getElementById('main');
const cats={};
TOOLS.forEach(t=>(cats[t.category]=cats[t.category]||[]).push(t));
for(const c in cats){
  const h=document.createElement('h3');h.textContent=c;side.appendChild(h);
  cats[c].forEach(t=>{
    const d=document.createElement('div');d.className='tool';d.dataset.id=t.id;
    d.innerHTML='<b>'+t.name+'</b><small>'+t.summary+'</small>';
    d.onclick=()=>select(t,d);side.appendChild(d);
  });
}
function select(t,el){
  document.querySelectorAll('.tool').forEach(x=>x.classList.remove('active'));
  el.classList.add('active');render(t);
}
function render(t){
  let f='<div class="card"><h2>'+t.name+' <span class="badge">'+t.category+
    '</span></h2><div class="muted">'+t.summary+'</div>';
  if(t.note)f+='<div class="note">'+t.note+'</div>';
  f+='<form id="f">';
  t.params.forEach(p=>{
    const id='p_'+p.key;
    if(p.kind==='flag'){
      f+='<div class="chk"><input type="checkbox" id="'+id+'"><label for="'+id+
        '" style="margin:0">'+p.label+'</label></div>';
    }else if(p.kind==='choice'){
      f+='<label>'+p.label+'</label><select id="'+id+'">'+
        p.choices.map(c=>'<option value="'+c+'">'+(c||'(none)')+'</option>').join('')+
        '</select>';
    }else if(p.kind==='text'){
      f+='<label>'+p.label+(p.required?' *':'')+'</label><textarea id="'+id+'"></textarea>';
    }else{
      f+='<label>'+p.label+(p.required?' *':'')+'</label><input type="text" id="'+id+
        '" value="'+(p.default==null?'':p.default)+'">';
    }
  });
  f+='<button type="submit">Run</button></form>'+
    '<div class="cmd" id="cmd"></div></div>'+
    '<div class="card"><pre id="out" class="muted">(no output yet)</pre></div>';
  main.innerHTML=f;
  document.getElementById('f').onsubmit=e=>{e.preventDefault();runTool(t);};
}
async function runTool(t){
  const values={};
  t.params.forEach(p=>{
    const el=document.getElementById('p_'+p.key);
    values[p.key]=p.kind==='flag'?el.checked:el.value;
  });
  const btn=document.querySelector('button');btn.disabled=true;btn.textContent='Running...';
  const out=document.getElementById('out');out.textContent='running...';out.className='';
  try{
    const r=await fetch('/api/run?k='+AUTH,{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({id:t.id,values})});
    const d=await r.json();
    document.getElementById('cmd').textContent='$ '+d.cmd;
    out.textContent=(d.output||'(no output)')+'\n[exit '+d.rc+']';
  }catch(err){out.textContent='request failed: '+err;}
  btn.disabled=false;btn.textContent='Run';
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
