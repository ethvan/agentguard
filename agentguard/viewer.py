"""Static HTML log viewer. `agentguard viewer` renders .agentguard/audit.jsonl into one self-contained page.

Filters (verdict / check / source / free text), a decision timeline, per-tool block rates,
and click-to-expand rows. Log text is attacker-influenced, so the page only ever uses textContent.
"""
from __future__ import annotations

import json
from pathlib import Path


def load_rows(path: Path) -> list[dict]:
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
    return rows


def render(rows: list[dict], title: str = "AgentGuard log") -> str:
    data = json.dumps(rows, ensure_ascii=False).replace("</", "<\\/").replace("<!--", "<\\!--")
    return TEMPLATE.replace("__DATA__", data).replace("__TITLE__", title)


def write(audit_path: Path, out: Path, title: str = "AgentGuard log") -> int:
    rows = load_rows(audit_path)
    Path(out).write_text(render(rows, title), encoding="utf-8")
    return sum(1 for r in rows if "final" in r)


TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#fafaf8;--fg:#1d1d1b;--mut:#6b6b66;--card:#fff;--line:#e4e3dd;--allow:#2f7d4f;--ask:#b7791f;--block:#c0392b;--acc:#3b5bdb}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--mut:#9a9992;--card:#1f1f1d;--line:#34342f;--allow:#5fbf86;--ask:#e0a93f;--block:#ef6b5b;--acc:#8fa6ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin:28px 0 8px}
.sub{color:var(--mut);margin-bottom:16px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card b{display:block;font-size:22px}.card span{color:var(--mut);font-size:12px}
.bar{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
select,input{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:7px 10px;font:inherit}
input{flex:1;min-width:180px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;overflow-x:auto}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px}tr:last-child td{border-bottom:0}
tr.row{cursor:pointer}tr.row:hover{background:color-mix(in srgb,var(--acc) 7%,transparent)}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.allow{color:var(--allow)}.ask{color:var(--ask)}.block{color:var(--block)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.detail td{background:color-mix(in srgb,var(--fg) 4%,transparent)}
pre{margin:0;white-space:pre-wrap;word-break:break-word}
.meter{height:8px;background:var(--line);border-radius:4px;overflow:hidden;min-width:80px}.meter i{display:block;height:100%;background:var(--block)}
.empty{color:var(--mut);padding:18px;text-align:center}
svg text{fill:var(--mut);font-size:10px}
</style></head><body><main>
<h1>__TITLE__</h1><div class="sub" id="range"></div>
<div class="cards" id="cards"></div>
<h2>Timeline</h2><div class="panel"><svg id="tl" width="100%" height="120" role="img" aria-label="Decisions over time"></svg></div>
<h2>Decisions</h2>
<div class="bar">
 <select id="fv"><option value="">all verdicts</option><option>allow</option><option>block</option></select>
 <select id="fp"><option value="">any policy verdict</option><option value="ask">needed approval</option><option value="block">policy block</option><option value="allow">policy allow</option></select>
 <select id="fc"><option value="">all checks</option></select>
 <select id="fs"><option value="">shell + mcp</option><option>shell</option><option>mcp</option></select>
 <input id="q" placeholder="search tool, arguments, reasons…">
</div>
<div class="panel"><table><thead><tr><th>Time</th><th>Source</th><th>Tool</th><th>Policy</th><th>Final</th><th>Why</th></tr></thead><tbody id="rows"></tbody></table><div class="empty" id="none" hidden>No decisions match.</div></div>
<h2>By tool</h2><div class="panel"><table><thead><tr><th>Tool</th><th>Calls</th><th>Blocked</th><th>Prompted</th><th>Block rate</th></tr></thead><tbody id="tools"></tbody></table></div>
<h2>Events</h2><div class="panel" id="events"></div>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
const all=JSON.parse(document.getElementById('data').textContent);
const calls=all.filter(r=>!r.event&&r.final), events=all.filter(r=>r.event);
const $=id=>document.getElementById(id);
const el=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e};
const fmt=ts=>new Date(ts*1000).toLocaleString();
const pill=v=>el('span','pill '+v,v);

// cards
const med=a=>{const s=a.map(r=>r.latency_ms).sort((x,y)=>x-y);return s.length?s[Math.floor(s.length/2)]:0};
const n=(f)=>calls.filter(f).length;
[['calls',calls.length],['allowed',n(r=>r.final==='allow')],['blocked',n(r=>r.final==='block')],
 ['prompted',n(r=>r.policy_verdict==='ask')],['median policy latency',med(calls).toFixed(2)+' ms']]
 .forEach(([k,v])=>{const c=el('div','card');c.append(el('b','',v),el('span','',k));$('cards').append(c)});
$('range').textContent=calls.length?fmt(calls[0].ts)+' → '+fmt(calls[calls.length-1].ts)+' · '+new Set(calls.map(r=>r.session)).size+' session(s)':'No decisions logged yet.';

// check filter options
[...new Set(calls.flatMap(r=>r.findings.map(f=>f.check)))].sort().forEach(c=>{const o=el('option','',c);o.value=c;$('fc').append(o)});

// timeline: stacked bars by time bucket
function timeline(rows){
  const svg=$('tl');svg.replaceChildren();
  if(!rows.length)return;
  const W=1000,H=120,pad=18,B=Math.min(40,Math.max(1,rows.length));
  const t0=rows[0].ts,t1=rows[rows.length-1].ts,span=Math.max(t1-t0,1e-6);
  const bk=Array.from({length:B},()=>({allow:0,ask:0,block:0}));
  rows.forEach(r=>{const i=Math.min(B-1,Math.floor((r.ts-t0)/span*B));
    bk[i][r.final==='block'?'block':(r.policy_verdict==='ask'?'ask':'allow')]++});
  const mx=Math.max(...bk.map(b=>b.allow+b.ask+b.block)),bw=(W-2*pad)/B;
  svg.setAttribute('viewBox',`0 0 ${W} ${H}`);
  const ns='http://www.w3.org/2000/svg';
  bk.forEach((b,i)=>{let y=H-pad;
    ['allow','ask','block'].forEach(k=>{if(!b[k])return;const h=b[k]/mx*(H-2*pad);y-=h;
      const r=document.createElementNS(ns,'rect');
      r.setAttribute('x',pad+i*bw+1);r.setAttribute('y',y);r.setAttribute('width',Math.max(bw-2,1));r.setAttribute('height',h);
      r.setAttribute('rx',2);r.setAttribute('fill',`var(--${k})`);
      const tt=document.createElementNS(ns,'title');tt.textContent=`${k}: ${b[k]}`;r.append(tt);svg.append(r)})});
  [[pad,fmt(t0)],[W-pad,fmt(t1)]].forEach(([x,t],i)=>{const e=document.createElementNS(ns,'text');
    e.setAttribute('x',x);e.setAttribute('y',H-4);e.setAttribute('text-anchor',i?'end':'start');e.textContent=t;svg.append(e)});
}

// decisions table
const argText=r=>JSON.stringify(r.arguments);
const why=r=>r.findings.length?r.findings.map(f=>`[${f.check}] ${f.reason}`):['no findings'];
function render(){
  const fv=$('fv').value,fp=$('fp').value,fc=$('fc').value,fs=$('fs').value,q=$('q').value.toLowerCase();
  const rows=calls.filter(r=>(!fv||r.final===fv)&&(!fp||r.policy_verdict===fp)&&(!fs||r.source===fs)
    &&(!fc||r.findings.some(f=>f.check===fc))
    &&(!q||(r.tool+' '+argText(r)+' '+why(r).join(' ')).toLowerCase().includes(q)));
  const tb=$('rows');tb.replaceChildren();
  rows.slice().reverse().forEach(r=>{
    const tr=el('tr','row');
    const tc=el('td','mono',r.tool);
    tr.append(el('td','',fmt(r.ts)),el('td','',r.source),tc);
    const p=el('td');p.append(pill(r.policy_verdict));
    const f=el('td');f.append(pill(r.final));
    tr.append(p,f,el('td','',why(r)[0]));
    const d=el('tr','detail');d.hidden=true;const dc=el('td');dc.colSpan=6;
    const pre=el('pre','mono',[`call ${r.call_id} · session ${r.session}${r.server?' · server '+r.server:''}`,
      ...(r.user_response?['user response: '+r.user_response]:[]),'', 'arguments:',JSON.stringify(r.arguments,null,2),'','findings:',...why(r),
      '',`policy latency ${r.latency_ms} ms`].join('\n'));
    dc.append(pre);d.append(dc);
    tr.onclick=()=>{d.hidden=!d.hidden};
    tb.append(tr,d)});
  $('none').hidden=rows.length>0;
  timeline(rows.slice().sort((a,b)=>a.ts-b.ts));
}
['fv','fp','fc','fs'].forEach(i=>$(i).onchange=render);$('q').oninput=render;

// per-tool
const byTool={};calls.forEach(r=>{const t=byTool[r.tool]??={n:0,b:0,a:0};t.n++;t.b+=r.final==='block';t.a+=r.policy_verdict==='ask'});
Object.entries(byTool).sort((a,b)=>b[1].b/b[1].n-a[1].b/a[1].n||b[1].n-a[1].n).forEach(([k,t])=>{
  const tr=el('tr');tr.append(el('td','mono',k),el('td','',t.n),el('td','',t.b),el('td','',t.a));
  const c=el('td'),m=el('div','meter'),i=el('i');i.style.width=(t.b/t.n*100)+'%';m.append(i);
  c.append(m,el('span','',Math.round(t.b/t.n*100)+'%'));tr.append(c);$('tools').append(tr)});

// events
if(!events.length)$('events').append(el('div','empty','No events.'));
events.forEach(e=>{const {ts,session,event,...rest}=e;
  $('events').append(el('div','',`${fmt(ts)} · ${event} · ${JSON.stringify(rest)}`))});
render();
</script></body></html>
"""
