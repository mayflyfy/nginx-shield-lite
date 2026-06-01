from http.server import BaseHTTPRequestHandler, HTTPServer
import re, json, os, subprocess

# ========== Config ==========
LOG_PATHS = ["/var/log/nginx/access.log", "/var/log/nginx/access.log.1"]
BLACKLIST_PATH = "/etc/nginx/conf.d/black_ip.conf"
PORT = 9999

BOTS = [
    ("Bingbot",      re.compile(r"bingbot", re.I)),
    ("Googlebot",    re.compile(r"googlebot", re.I)),
    ("BaiduSpider",  re.compile(r"baiduspider", re.I)),
    ("DuckDuckBot",  re.compile(r"duckduckbot", re.I)),
    ("YandexBot",    re.compile(r"yandexbot", re.I)),
    ("NaverBot",     re.compile(r"naverbot", re.I)),
    ("SogouSpider",  re.compile(r"sogou\sspider", re.I)),
    ("360Spider",    re.compile(r"360spider", re.I)),
    ("ShenmaSpider", re.compile(r"shenma", re.I)),
]

IP_PATTERN = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
STATUS_PATTERN = re.compile(r"\" (\d{3}) ")

# ========== HTML ==========
HTML = """<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>Nginx日志分析</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:monospace;background:#fff;color:#333;padding:16px;font-size:13px}
h2{font-size:15px;margin:0 0 8px;padding-bottom:4px;border-bottom:1px solid #ddd}
.row{display:flex;gap:16px}
.col{flex:1;min-width:0}
table{border-collapse:collapse;width:100%;margin-bottom:8px}
th,td{border:1px solid #ddd;padding:4px 8px;text-align:left}
th{background:#f5f5f5}
tr:nth-child(even){background:#fafafa}
input[type=number]{width:50px;padding:2px 4px;font-family:monospace;font-size:13px}
.btn{background:#fff;border:1px solid #999;padding:4px 14px;cursor:pointer;font-family:monospace;font-size:13px}
.btn:hover{background:#eee}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn-sm{padding:2px 8px;font-size:12px}
textarea{width:100%;height:260px;border:1px solid #ddd;padding:6px;font-family:monospace;font-size:12px;resize:vertical}
#msg{margin:4px 0;font-size:12px}
#cmd_msg{margin:6px 0;font-size:12px;white-space:pre-wrap}
.loading{color:#999}
label{font-size:12px;font-weight:normal;margin-left:8px}
</style>
</head>
<body>
<div class="row">
<div class="col">
<h2>爬虫访问统计 <label><input id="today_only" type="checkbox"> 只看当天</label><label><input id="success_only" type="checkbox"> 只看成功请求</label></h2>
<div id="bot_stats" class="loading">加载中...</div>
<h2 style="margin-top:12px">IP访问次数明细（去重）</h2>
<div style="margin-bottom:6px">只看访问次数 ≥ <input id="ip_min" type="number" min="0" value="5"> 的IP　排序：<label><input id="sort_count" name="ip_sort" type="radio" checked> 访问量</label><label><input id="sort_ip" name="ip_sort" type="radio"> IP地址</label></div>
<div id="ip_stats" class="loading">加载中...</div>
</div>
<div class="col">
<h2>IP黑名单编辑 <span style="font-size:11px;color:#888">/etc/nginx/conf.d/black_ip.conf</span></h2>
<div id="msg"></div>
<textarea id="blacklist" spellcheck="false"></textarea>
<br>
<button class="btn" onclick="checkDup()">检查重复</button>
<button class="btn" onclick="sortBlacklist()">按IP排序</button>
<button class="btn" onclick="saveBlacklist()">保存</button>
<button class="btn" onclick="loadBlacklist()">重新加载</button>
<h2 style="margin-top:12px">Nginx操作</h2>
<div>
<button class="btn" id="btn_test" onclick="nginxTest()">检查配置</button>
<button class="btn" id="btn_reload" onclick="nginxReload()" disabled>重载Nginx</button>
</div>
<div id="cmd_msg"></div>
</div>
</div>

<script>
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

function renderBot(data){
    if(data.error){document.getElementById('bot_stats').innerHTML='<p style="color:red">'+esc(data.error)+'</p>';return}
    let h='<table><tr><th>爬虫</th><th>访问次数</th></tr>';
    let total=0;
    for(let k in data)if(k!=='total'){h+='<tr><td>'+esc(k)+'</td><td>'+data[k]+'</td>';total+=data[k]}
    h+='<tr style="font-weight:bold"><td>合计（匹配爬虫）</td><td>'+total+'</td></tr>';
    h+='<tr><td>日志总行数</td><td>'+data.total+'</td></tr></table>';
    document.getElementById('bot_stats').innerHTML=h;
}

function getCookie(k){const m=document.cookie.match(new RegExp('(?:^|;)\\s*'+k+'=([^;]*)'));return m?decodeURIComponent(m[1]):null}
function setCookie(k,v){document.cookie=k+'='+encodeURIComponent(v)+';path=/;max-age=31536000'}

function ipSortKey(ip){return ip.split('.').map(n=>n.padStart(3,'0')).join('')}

function renderIP(data){
    if(data.error){document.getElementById('ip_stats').innerHTML='<p style="color:red">'+esc(data.error)+'</p>';return}
    const min=parseInt(document.getElementById('ip_min').value)||0;
    const filtered=data.filter(x=>x[1]>=min);
    const byIp=document.getElementById('sort_ip').checked;
    const sorted=filtered.slice().sort((a,b)=>byIp?ipSortKey(a[0]).localeCompare(ipSortKey(b[0])):b[1]-a[1]);
    if(!sorted.length){document.getElementById('ip_stats').innerHTML='<p>无符合条件的数据</p>';return}
    let h='<table><tr><th>#</th><th>IP</th><th>访问次数</th><th>操作</th></tr>';
    for(let i=0;i<sorted.length;i++){
        h+='<tr><td>'+(i+1)+'</td><td>'+esc(sorted[i][0])+'</td><td>'+sorted[i][1]+'</td>';
        h+='<td><button class="btn btn-sm" onclick="addBlacklist(\\''+sorted[i][0]+'\\')">加入黑名单</button></td></tr>';
    }
    h+='</table><p>筛选结果: '+sorted.length+' / 总去重IP: '+data.length+'</p>';
    document.getElementById('ip_stats').innerHTML=h;
}

let allIPs=[];
function loadStats(){
    const p=new URLSearchParams();
    if(document.getElementById('today_only').checked)p.set('today','1');
    if(document.getElementById('success_only').checked)p.set('success','1');
    const qs=p.toString();
    fetch('api/stats'+(qs?'?'+qs:'')).then(r=>r.json()).then(d=>{
        renderBot(d.bots);allIPs=d.ips;renderIP(allIPs);
    }).catch(e=>{document.getElementById('bot_stats').innerHTML='<p style="color:red">请求失败</p>'});
}

function addBlacklist(ip){
    const ta=document.getElementById('blacklist');
    const content=ta.value;
    const lines=content.split('\\n').map(l=>l.trim().split(/\\s+/)[0]).filter(Boolean);
    if(lines.includes(ip)){alert(ip+' 已在黑名单中');return}
    const add=ip+' 1;';
    ta.value=content?(content.rstrip?content.rstrip('\\n'):content.replace(/\\n+$/,''))+'\\n'+add:add;
    document.getElementById('msg').textContent='已添加 '+ip+'，请保存';
    document.getElementById('msg').style.color='green';
}

document.getElementById('ip_min').addEventListener('change',function(){
    setCookie('ip_min',this.value);renderIP(allIPs);
});
document.getElementById('sort_count').addEventListener('change',function(){renderIP(allIPs)});
document.getElementById('sort_ip').addEventListener('change',function(){renderIP(allIPs)});
document.getElementById('today_only').addEventListener('change',function(){
    setCookie('today_only',this.checked?'1':'0');loadStats();
});
document.getElementById('success_only').addEventListener('change',function(){
    setCookie('success_only',this.checked?'1':'0');loadStats();
});
(function(){
    const v=getCookie('ip_min');if(v)document.getElementById('ip_min').value=v;
    const t=getCookie('today_only');if(t==='1')document.getElementById('today_only').checked=true;
    const s=getCookie('success_only');if(s==='1')document.getElementById('success_only').checked=true;
})();

function loadBlacklist(){
    fetch('api/blacklist').then(r=>r.json()).then(d=>{
        document.getElementById('blacklist').value=d.content||'';
        document.getElementById('msg').textContent='';
    }).catch(e=>{document.getElementById('msg').textContent='加载失败'});
}

function sortBlacklist(){
    const ta=document.getElementById('blacklist');
    const lines=ta.value.split('\\n').filter(l=>l.trim());
    lines.sort((a,b)=>{
        const ka=a.trim().split(/\\s+/)[0],kb=b.trim().split(/\\s+/)[0];
        return ipSortKey(ka).localeCompare(ipSortKey(kb));
    });
    ta.value=lines.join('\\n');
    document.getElementById('msg').textContent='已按IP排序';
    document.getElementById('msg').style.color='green';
}

function findDupLines(content){
    const lines=content.split('\\n').filter(l=>l.trim());
    const seen={}, dups=[];
    lines.forEach((l,i)=>{
        const key=l.trim().split(/\\s+/)[0];
        if(!key)return;
        if(seen[key]!==undefined){dups.push({line:i+1,ip:key,first:seen[key]+1})}
        else{seen[key]=i}
    });
    return dups;
}

function checkDup(){
    const dups=findDupLines(document.getElementById('blacklist').value);
    const msg=document.getElementById('msg');
    if(!dups.length){msg.textContent='无重复IP';msg.style.color='green'}
    else{msg.textContent='发现'+dups.length+'个重复: '+dups.map(d=>d.ip+'(第'+d.first+'行与第'+d.line+'行)').join(', ');msg.style.color='red'}
    return dups;
}

function saveBlacklist(){
    const dups=checkDup();
    if(dups.length){if(!confirm('存在'+dups.length+'个重复IP，仍要保存？'))return}
    const content=document.getElementById('blacklist').value;
    document.getElementById('msg').textContent='保存中...';document.getElementById('msg').style.color='#333';
    fetch('api/blacklist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:content})})
    .then(r=>r.json()).then(d=>{
        document.getElementById('msg').textContent=d.ok?'保存成功':'保存失败: '+(d.error||'');
        document.getElementById('msg').style.color=d.ok?'green':'red';
    }).catch(e=>{document.getElementById('msg').textContent='保存失败';document.getElementById('msg').style.color='red'});
}

function nginxTest(){
    const cm=document.getElementById('cmd_msg');
    cm.textContent='检查中...';cm.style.color='#333';
    document.getElementById('btn_reload').disabled=true;
    fetch('api/nginx_test').then(r=>r.json()).then(d=>{
        cm.textContent=d.output||'';
        cm.style.color=d.ok?'green':'red';
        document.getElementById('btn_reload').disabled=!d.ok;
    }).catch(e=>{cm.textContent='请求失败';cm.style.color='red'});
}

function nginxReload(){
    const cm=document.getElementById('cmd_msg');
    cm.textContent='重载中...';cm.style.color='#333';
    fetch('api/nginx_reload').then(r=>r.json()).then(d=>{
        cm.textContent=d.output||'';
        cm.style.color=d.ok?'green':'red';
    }).catch(e=>{cm.textContent='请求失败';cm.style.color='red'});
}

loadStats();
loadBlacklist();
</script>
</body>
</html>"""


def analyze_logs(paths=None, success_only=False):
    if paths is None:
        paths = LOG_PATHS
    bot_counts = {name: 0 for name, _ in BOTS}
    bot_counts["total"] = 0
    ip_counts = {}

    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if success_only:
                        m_status = STATUS_PATTERN.search(line)
                        if m_status and m_status.group(1).startswith("4"):
                            continue
                    bot_counts["total"] += 1
                    for name, pat in BOTS:
                        if pat.search(line):
                            bot_counts[name] += 1
                            break
                    m = IP_PATTERN.match(line)
                    if m:
                        ip = m.group(1)
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        except FileNotFoundError:
            pass

    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    return bot_counts, sorted_ips


def read_blacklist():
    try:
        with open(BLACKLIST_PATH, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""
    except Exception:
        return None


def write_blacklist(content):
    try:
        with open(BLACKLIST_PATH, "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except Exception:
        return False


def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        output = (r.stdout + r.stderr).strip()
        return r.returncode == 0, output
    except Exception as e:
        return False, str(e)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML.encode("utf-8"))
        elif self.path.startswith("/api/stats"):
            qs = self.path.split("?", 1)[-1] if "?" in self.path else ""
            today = "today=1" in qs
            success = "success=1" in qs
            paths = [LOG_PATHS[0]] if today else LOG_PATHS
            bot_counts, sorted_ips = analyze_logs(paths, success_only=success)
            data = {"bots": bot_counts, "ips": sorted_ips}
            self._json(data)
        elif self.path == "/api/blacklist":
            content = read_blacklist()
            if content is None:
                self._json({"error": "读取失败"}, 500)
            else:
                self._json({"content": content})
        elif self.path == "/api/nginx_test":
            ok, output = run_cmd("nginx -t 2>&1")
            self._json({"ok": ok, "output": output})
        elif self.path == "/api/nginx_reload":
            ok, output = run_cmd("nginx -s reload 2>&1")
            self._json({"ok": ok, "output": output})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/blacklist":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body)
                content = data.get("content", "")
            except Exception:
                self._json({"error": "无效请求"}, 400)
                return
            if write_blacklist(content):
                self._json({"ok": True})
            else:
                self._json({"error": "写入失败"}, 500)
        else:
            self.send_response(404)
            self.end_headers()

    def _json(self, data, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Server started at: http://0.0.0.0:{PORT}")
    server.serve_forever()
