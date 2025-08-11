/*
  Cloudflare Clean IP Scanner (static, client-side)
  - Fetches Cloudflare CIDR lists (v4)
  - Samples N IPs from ranges
  - Measures "ping" using browser techniques (fetch no-cors + Image fallback)
  - Sorts, filters, and displays with animated UI
  NOTE: Browser-based ping is an approximation. For high reliability use a server-side probe.
*/

// --- Config / utility ---
const CF_IPS_V4 = 'https://www.cloudflare.com/ips-v4'; // official list (plain text)
const CF_IPS_V6 = 'https://www.cloudflare.com/ips-v6'; // not used in this demo but could be
const MAX_CONCURRENT = 12; // how many concurrent probes
const TIMEOUT_MS = 4000;

function cidrToRange(cidr){
  // returns [baseInt, size] for IPv4 CIDR, and a helper to pick random IPs
  const [ip, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr,10);
  const parts = ip.split('.').map(n=>parseInt(n,10));
  const base = ((parts[0]<<24)>>>0) + ((parts[1]<<16)>>>0) + ((parts[2]<<8)>>>0) + (parts[3]>>>0);
  const size = Math.pow(2, 32 - prefix);
  return { base: base>>>0, size: size };
}
function intToIp(i){
  return [(i>>>24)&0xFF, (i>>>16)&0xFF, (i>>>8)&0xFF, i&0xFF].join('.');
}
function randBetween(a,b){
  return Math.floor(Math.random()*(b-a))+a;
}

// --- DOM refs ---
const scanBtn = document.getElementById('scanBtn');
const stopBtn = document.getElementById('stopBtn');
const countInput = document.getElementById('count');
const maxLatencyInput = document.getElementById('maxLatency');
const listEl = document.getElementById('list');
const foundCountEl = document.getElementById('foundCount');
const avgPingEl = document.getElementById('avgPing');
const elapsedEl = document.getElementById('elapsed');
const sortSelect = document.getElementById('sortSelect');
const copyBtn = document.getElementById('copyBtn');
const exportBtn = document.getElementById('exportBtn');
const themeBtns = document.querySelectorAll('.theme-btn');
const tGreen = document.getElementById('t-green');
const tYellow = document.getElementById('t-yellow');
const tRed = document.getElementById('t-red');

let running = false;
let abortController = null;
let allResults = [];
let startTime = null;
let timerInterval = null;

// --- fetch Cloudflare CIDRs ---
async function fetchCidrs(){
  try{
    const res = await fetch(CF_IPS_V4, {cache:'no-cache'});
    if(!res.ok) throw new Error('failed to fetch cidrs');
    const txt = await res.text();
    const lines = txt.split('\n').map(s=>s.trim()).filter(s=>s && !s.startsWith('#'));
    // filter only IPv4 CIDRs
    const v4s = lines.filter(l=>l.indexOf(':')===-1);
    return v4s;
  }catch(e){
    console.warn('CIDR fetch failed', e);
    throw e;
  }
}

// --- sample IPs from CIDRs ---
function sampleIpsFromCidrs(cidrs, count){
  const parsed = cidrs.map(c=>({cidr:c, ...cidrToRange(c)}));
  const ips = [];
  // simple weighted sampling proportional to size to get distributed picks
  const totalSize = parsed.reduce((s,p)=>s + Math.min(p.size, 65536), 0);
  while(ips.length < count){
    // pick a CIDR randomly weighted
    const r = Math.random()*totalSize;
    let acc = 0;
    let chosen = parsed[0];
    for(const p of parsed){
      acc += Math.min(p.size, 65536);
      if(r <= acc){ chosen = p; break; }
    }
    const offset = Math.floor(Math.random() * Math.min(chosen.size, 65536));
    const ipInt = (chosen.base + offset) >>>0;
    const ip = intToIp(ipInt);
    if(!ips.includes(ip)) ips.push(ip);
    if(ips.length > count*3) break; // safety
  }
  return ips.slice(0,count);
}

// --- ping (browser) ---
function timeoutPromise(ms, p){
  return new Promise((resolve, reject)=>{
    const t = setTimeout(()=>reject(new Error('timeout')), ms);
    p.then(r=>{ clearTimeout(t); resolve(r) }).catch(err=>{ clearTimeout(t); reject(err) });
  });
}

// approach: 1) try fetch to https://<ip>/?_t=ts (no-cors) and measure. 2) fallback to Image object to http://<ip>/favicon.ico
async function probeIp(ip, timeout=TIMEOUT_MS){
  const stamp = () => performance.now();
  // We'll try multiple attempts for more stable reading
  const attempts = 2;
  for(let attempt=0; attempt<attempts; attempt++){
    const t1 = stamp();
    try{
      // use fetch to https (may be blocked by cert) but no-cors to still allow timing
      const url = `https://${ip}/?t=${Date.now()}`;
      const p = fetch(url, {mode:'no-cors', cache:'no-store', credentials:'omit'});
      await timeoutPromise(timeout, p);
      const t2 = stamp();
      return Math.max(1, Math.round(t2 - t1));
    }catch(e){
      // fallback to image (http)
      try{
        const t3 = stamp();
        await new Promise((resolve, reject)=>{
          const img = new Image();
          let done = false;
          const timer = setTimeout(()=>{ if(!done){ done=true; reject(new Error('timeout')); } }, timeout);
          img.onload = ()=>{ if(!done){ done=true; clearTimeout(timer); resolve(); } };
          img.onerror = ()=>{ if(!done){ done=true; clearTimeout(timer); resolve(); } }; // error still means connection attempt happened
          img.src = `http://${ip}/favicon.ico?t=${Date.now()}`;
        });
        const t4 = stamp();
        return Math.max(1, Math.round(t4 - t3));
      }catch(_){
        // continue to next attempt
      }
    }
  }
  // final: failed
  throw new Error('unreachable');
}

// --- UI helpers ---
function addRow(result){
  const row = document.createElement('div');
  row.className = 'row ' + (result.ping===null ? 'gray' : (result.ping <= parseInt(tGreen.value) ? 'green' : result.ping <= parseInt(tYellow.value) ? 'yellow' : 'red'));
  row.innerHTML = `
    <div class="meta">
      <div class="ip-badge">${result.ip}</div>
      <div class="status">${result.source}</div>
    </div>
    <div style="display:flex;align-items:center;gap:12px">
      <div class="lat">${result.ping===null? '—': result.ping + ' ms'}</div>
      <div class="small status">${result.ok ? 'OK' : 'Timed/Blocked'}</div>
    </div>
  `;
  // insert sorted (top) for nice UX
  listEl.prepend(row);
}

function renderAll(){
  listEl.innerHTML = '';
  const sorted = sortResults(allResults, sortSelect.value);
  for(const r of sorted) addRow(r);
  const oks = allResults.filter(r=>r.ok && r.ping!==null);
  foundCountEl.textContent = oks.length;
  const avg = oks.length ? Math.round(oks.reduce((s,a)=>s+a.ping,0)/oks.length) : '—';
  avgPingEl.textContent = (avg==='—'? '—' : (avg + ' ms'));
}

// sorting
function sortResults(arr, mode){
  const copy = arr.slice();
  if(mode === 'lat_asc') copy.sort((a,b)=> (a.ping||99999) - (b.ping||99999));
  else if(mode === 'lat_desc') copy.sort((a,b)=> (b.ping||0) - (a.ping||0));
  else if(mode === 'ip_asc') copy.sort((a,b)=> ipToNum(a.ip) - ipToNum(b.ip));
  else if(mode === 'ip_desc') copy.sort((a,b)=> ipToNum(b.ip) - ipToNum(a.ip));
  return copy;
}
function ipToNum(ip){
  const p = ip.split('.').map(n=>parseInt(n,10));
  return ((p[0]<<24)>>>0) + ((p[1]<<16)>>>0) + ((p[2]<<8)>>>0) + (p[3]>>>0);
}

// --- main scan logic ---
async function startScan(){
  running = true;
  abortController = new AbortController();
  scanBtn.disabled = true;
  stopBtn.disabled = false;
  listEl.innerHTML = '';
  allResults = [];
  startTime = Date.now();
  timerInterval = setInterval(()=> {
    const s = Math.floor((Date.now()-startTime)/1000);
    elapsedEl.textContent = new Date(s*1000).toISOString().substr(11,8);
  }, 300);

  try{
    const cidrs = await fetchCidrs();
    const count = Math.max(1, Math.min(200, parseInt(countInput.value) || 30));
    const ips = sampleIpsFromCidrs(cidrs, count);
    // concurrency pool
    let idx = 0;
    const pool = new Array(Math.min(MAX_CONCURRENT, ips.length)).fill(0).map(async ()=>{
      while(running && idx < ips.length){
        const i = idx++;
        const ip = ips[i];
        const result = { ip, ping: null, ok:false, source:'sampled' };
        allResults.push(result);
        renderAll();
        try{
          const latency = await probeIp(ip, TIMEOUT_MS);
          result.ping = latency;
          result.ok = latency <= parseInt(maxLatencyInput.value);
        }catch(err){
          result.ping = null;
          result.ok = false;
        }
        renderAll();
      }
    });
    await Promise.all(pool);
  }catch(e){
    alert('خطا در گرفتن لیست CIDR از Cloudflare:\n' + (e.message || e));
  }finally{
    running = false;
    scanBtn.disabled = false;
    stopBtn.disabled = true;
    clearInterval(timerInterval);
  }
}

function stopScan(){
  running = false;
  if(abortController) abortController.abort();
  scanBtn.disabled = false;
  stopBtn.disabled = true;
  clearInterval(timerInterval);
}

// --- extra actions ---
copyBtn.addEventListener('click', async ()=>{
  const oks = allResults.filter(r=>r.ok && r.ping!==null).map(r=>r.ip);
  if(oks.length === 0){ alert('هیچ IP پاکی برای کپی وجود ندارد'); return; }
  try{
    await navigator.clipboard.writeText(oks.join('\n'));
    alert('کپی شد — ' + oks.length + ' آی‌پی');
  }catch(e){
    prompt('کپی اتوماتیک ناموفق بود — از این لیست کپی کن:', oks.join('\n'));
  }
});

exportBtn.addEventListener('click', ()=>{
  const rows = allResults.map(r=>`${r.ip},${r.ping===null?'':r.ping},${r.ok?1:0}`).join('\n');
  const csv = 'ip,ping_ms,clean\n' + rows;
  const blob = new Blob([csv], {type:'text/csv'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'cloudflare_ips.csv'; a.click();
  URL.revokeObjectURL(url);
});

scanBtn.addEventListener('click', startScan);
stopBtn.addEventListener('click', stopScan);
sortSelect.addEventListener('change', renderAll);

// theme buttons
themeBtns.forEach(b=>{
  b.addEventListener('click', ()=>{
    const t = b.dataset.theme;
    if(t==='low'){ tGreen.value=100; tYellow.value=200; tRed.value=400 }
    if(t==='med'){ tGreen.value=150; tYellow.value=300; tRed.value=600 }
    if(t==='high'){ tGreen.value=300; tYellow.value=600; tRed.value=1200 }
    if(t==='rgb'){ // disco background
      const bg = document.getElementById('bgEffect');
      bg.style.animation = 'rotate 6s linear infinite';
    }
    renderAll();
  });
});

// helper: re-render on threshold change
[tGreen,tYellow,tRed].forEach(inp=> inp.addEventListener('input', renderAll));

function init(){
  // small demo: nothing
}

init();
