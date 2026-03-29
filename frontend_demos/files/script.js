/* ═══════════════════════════════════════════════════════════════
   AEGIS IDS — SIMULATION ENGINE + UI CONTROLLER
   ═══════════════════════════════════════════════════════════════ */

'use strict';

// ── Globals ──────────────────────────────────────────────────────
const State = {
  isAnomaly:       false,
  anomalyTimeout:  null,
  packetCount:     142857,
  uniqueIPs:       384,
  threatsBlocked:  27,
  pktRate:         0,
  avgSize:         512,
  uptime:          0,
  alertCount:      0,
  blockedIPSet:    new Set(),
  connRows:        [],
  logEntries:      [],
};

const PROTOCOLS = ['TCP','UDP','ICMP','HTTP','HTTPS','DNS','SSH','FTP'];
const PROTO_COLORS = ['#00ffaa','#00c8ff','#a855f7','#ffd600','#ff6b35','#00e5ff','#ff2d55','#69ffb4'];

const ATTACK_TYPES = [
  'DDoS Flood', 'SQL Injection', 'Port Scan', 'Brute Force',
  'MITM Attack', 'XSS Attempt', 'DNS Spoofing', 'ARP Poisoning',
  'Zero-Day Exploit', 'Ransomware Beacon',
];
const COUNTRIES = [
  'CN','RU','KP','IR','BR','US','DE','IN','TR','UA','RO','NG'
];
const ATTACKER_IPS = () => {
  const oct = () => Math.floor(Math.random()*256);
  return `${oct()}.${oct()}.${oct()}.${oct()}`;
};
const PORTS = [22,80,443,3306,8080,21,25,53,135,445,3389,1433,27017,6379];

// ── Clock & Uptime ────────────────────────────────────────────────
function startClock() {
  const clock   = document.getElementById('clockDisplay');
  const uptime  = document.getElementById('uptimeCounter');
  setInterval(() => {
    const now = new Date();
    clock.textContent = now.toUTCString().slice(17, 25);
    State.uptime++;
    const h = String(Math.floor(State.uptime/3600)).padStart(2,'0');
    const m = String(Math.floor((State.uptime%3600)/60)).padStart(2,'0');
    const s = String(State.uptime%60).padStart(2,'0');
    uptime.textContent = `${h}:${m}:${s}`;
  }, 1000);
}

// ── Sparkline Charts ──────────────────────────────────────────────
function makeSparkline(id, color) {
  const data = Array.from({length:12}, ()=> Math.random()*100);
  const ctx = document.getElementById(id).getContext('2d');
  return new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.map((_,i)=>i),
      datasets:[{
        data,
        borderColor: color,
        borderWidth: 1.5,
        fill: true,
        backgroundColor: color.replace('rgb','rgba').replace(')',',0.08)') || 'rgba(0,255,170,0.08)',
        tension: 0.4,
        pointRadius: 0,
      }]
    },
    options: {
      responsive: false,
      animation: false,
      plugins: { legend: {display:false}, tooltip: {enabled:false} },
      scales:  { x:{display:false}, y:{display:false} },
    }
  });
}

const sparkCharts = {};
function initSparklines() {
  sparkCharts.packets = makeSparkline('sparkPackets', '#00ffaa');
  sparkCharts.size    = makeSparkline('sparkSize',    '#00c8ff');
  sparkCharts.ips     = makeSparkline('sparkIPs',     '#00c8ff');
  sparkCharts.threats = makeSparkline('sparkThreats', '#ff2d55');
}

function pushSparkData(chart, val, max=200) {
  const ds = chart.data.datasets[0];
  ds.data.push(val);
  if (ds.data.length > 20) ds.data.shift();
  chart.data.labels = ds.data.map((_,i)=>i);
  chart.update('none');
}

// ── Main Traffic Chart ────────────────────────────────────────────
let trafficChart;
const TRAFFIC_POINTS = 40;
const trafficNormal  = Array.from({length:TRAFFIC_POINTS}, ()=> 50+Math.random()*50);
const trafficAnomaly = Array.from({length:TRAFFIC_POINTS}, ()=> 0);
const trafficColors  = Array.from({length:TRAFFIC_POINTS}, ()=> 'rgba(0,255,170,0.7)');

function initTrafficChart() {
  const ctx = document.getElementById('trafficChart').getContext('2d');
  trafficChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: trafficNormal.map((_,i)=>i),
      datasets: [
        {
          label: 'Normal Traffic',
          data: [...trafficNormal],
          backgroundColor: trafficColors.map(c=>c),
          borderColor:     trafficColors.map(c=>c.replace('0.7','1')),
          borderWidth: 0,
          borderRadius: 2,
        },
        {
          label: 'Anomaly Spike',
          data: [...trafficAnomaly],
          backgroundColor: 'rgba(255,45,85,0.65)',
          borderColor: 'rgba(255,45,85,1)',
          borderWidth: 0,
          borderRadius: 2,
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 200 },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(3,11,18,0.95)',
          borderColor: 'rgba(0,255,170,0.2)',
          borderWidth: 1,
          titleFont: { family: "'Share Tech Mono'", size: 11 },
          bodyFont:  { family: "'Share Tech Mono'", size: 10 },
          titleColor: '#00ffaa',
          bodyColor: '#a8d4c2',
        }
      },
      scales: {
        x: {
          display: false,
          stacked: false,
          grid: { display: false },
        },
        y: {
          stacked: false,
          grid: {
            color: 'rgba(0,255,170,0.05)',
            drawBorder: false,
          },
          ticks: {
            font: { family: "'Share Tech Mono'", size: 9 },
            color: 'rgba(168,212,194,0.3)',
            callback: v => v + ' Mbps',
            maxTicksLimit: 4,
          },
          border: { display: false },
        }
      }
    }
  });
}

function updateTrafficChart() {
  const ds0 = trafficChart.data.datasets[0];
  const ds1 = trafficChart.data.datasets[1];

  // Shift left
  ds0.data.shift(); ds0.data.push(State.isAnomaly ? 20+Math.random()*30 : 45+Math.random()*65);
  ds1.data.shift(); ds1.data.push(State.isAnomaly ? 80+Math.random()*120 : 0);

  // Colors
  ds0.backgroundColor = ds0.data.map((v,i) => {
    const last = ds0.data.length - 1;
    return i === last ? 'rgba(0,255,170,0.9)' : 'rgba(0,255,170,0.4)';
  });

  trafficChart.data.labels = ds0.data.map((_,i)=>i);
  trafficChart.update('none');
}

// ── Protocol Donut ────────────────────────────────────────────────
let protoChart;
const protoData = [34, 22, 14, 12, 8, 5, 3, 2];

function initProtoChart() {
  const ctx = document.getElementById('protoChart').getContext('2d');
  protoChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: PROTOCOLS,
      datasets:[{
        data: [...protoData],
        backgroundColor: PROTO_COLORS.map(c=>c+'33'),
        borderColor: PROTO_COLORS,
        borderWidth: 1.5,
        hoverBackgroundColor: PROTO_COLORS.map(c=>c+'66'),
      }]
    },
    options: {
      responsive: false,
      cutout: '68%',
      animation: { duration: 400 },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(3,11,18,0.95)',
          borderColor: 'rgba(0,255,170,0.2)',
          borderWidth: 1,
          titleFont: { family: "'Share Tech Mono'", size: 10 },
          bodyFont:  { family: "'Share Tech Mono'", size: 10 },
          titleColor: '#00ffaa',
          bodyColor: '#a8d4c2',
        }
      }
    }
  });

  // Legend
  const leg = document.getElementById('protoLegend');
  PROTOCOLS.forEach((p,i) => {
    const item = document.createElement('div');
    item.className = 'proto-legend-item';
    item.innerHTML = `
      <div class="proto-dot" style="background:${PROTO_COLORS[i]};box-shadow:0 0 5px ${PROTO_COLORS[i]}"></div>
      <span class="proto-name">${p}</span>
      <span class="proto-pct" id="protoVal${i}">${protoData[i]}%</span>
    `;
    leg.appendChild(item);
  });
}

function updateProtoChart() {
  // Slightly drift values
  const ds = protoChart.data.datasets[0];
  let total = 0;
  ds.data = ds.data.map(v => {
    const n = Math.max(1, v + (Math.random()-.5)*2);
    total += n; return n;
  });
  // Re-normalize
  const sum = ds.data.reduce((a,b)=>a+b,0);
  ds.data = ds.data.map(v=>v/sum*100);
  protoChart.update('none');

  ds.data.forEach((v,i) => {
    const el = document.getElementById(`protoVal${i}`);
    if (el) el.textContent = v.toFixed(1)+'%';
  });

  const totalPkts = Math.floor(State.packetCount/1000);
  const el = document.getElementById('donutTotal');
  if (el) el.textContent = totalPkts+'K';
}

// ── Stat Card Updates ─────────────────────────────────────────────
function animateCount(el, newVal, prefix='', suffix='') {
  el.classList.remove('count-update');
  void el.offsetWidth;
  el.textContent = prefix + newVal.toLocaleString() + suffix;
  el.classList.add('count-update');
}

function updateStats() {
  State.pktRate  = Math.floor(State.isAnomaly ? 800+Math.random()*1200 : 200+Math.random()*400);
  State.packetCount += State.pktRate;
  State.avgSize  = Math.floor(State.isAnomaly ? 900+Math.random()*600 : 400+Math.random()*300);
  State.uniqueIPs += Math.floor(Math.random()*(State.isAnomaly?12:3));

  const pEl = document.getElementById('packetCount');
  const sEl = document.getElementById('avgSize');
  const iEl = document.getElementById('uniqueIPs');
  const tEl = document.getElementById('threatsBlocked');

  if (pEl) pEl.textContent = State.packetCount.toLocaleString();
  if (sEl) sEl.innerHTML   = State.avgSize + ' <span class="stat-unit">B</span>';
  if (iEl) iEl.textContent = State.uniqueIPs.toLocaleString();
  if (tEl) tEl.textContent = State.threatsBlocked.toLocaleString();

  // Deltas
  setDelta('packetDelta', `↑ +${State.pktRate.toLocaleString()}/s`, 'positive');
  setDelta('sizeDelta',   State.isAnomaly ? '↑ spike detected' : '─ stable', State.isAnomaly ? 'negative':'neutral');
  setDelta('ipDelta',     `↑ +${Math.floor(Math.random()*5)} new`, 'positive');
  setDelta('threatDelta', `↑ +${State.isAnomaly?Math.floor(Math.random()*5):0} events`, State.isAnomaly?'negative':'neutral');

  // Sparklines
  pushSparkData(sparkCharts.packets, State.pktRate, 2000);
  pushSparkData(sparkCharts.size,    State.avgSize, 1500);
  pushSparkData(sparkCharts.ips,     Math.floor(Math.random()*10), 15);
  pushSparkData(sparkCharts.threats, State.isAnomaly ? Math.floor(Math.random()*8) : 0, 10);

  // Footer
  const mbps = (State.pktRate * State.avgSize * 8 / 1e6).toFixed(1);
  const lat  = Math.floor(State.isAnomaly ? 80+Math.random()*120 : 5+Math.random()*25);
  const drop = State.isAnomaly ? (Math.random()*3).toFixed(2) : (Math.random()*0.1).toFixed(2);

  el('throughput', `${mbps} Mbps`);
  el('latency',    `${lat} ms`);
  el('dropRate',   `${drop}%`);
}

function setDelta(id, text, cls) {
  const e = document.getElementById(id);
  if (!e) return;
  e.textContent = text;
  e.className = `stat-delta ${cls}`;
}

function el(id, text) {
  const e = document.getElementById(id);
  if (e) e.textContent = text;
}

// ── Activity Log ──────────────────────────────────────────────────
const LOG_NORMALS = [
  'Connection established from 192.168.1.{r}',
  'Packet inspection complete · 0 anomalies',
  'ML model inference: BENIGN (conf 99.{r}%)',
  'TCP handshake OK · port {p}',
  'Flow classified: NORMAL by LSTM layer',
  'DNS query resolved · latency {r}ms',
  'TLS 1.3 session established',
  'Heartbeat ACK from gateway 10.0.0.1',
  'IDS signature DB updated · 47,{r} rules',
  'HTTPS traffic analyzed · clean',
];
const LOG_ATTACKS = [
  '⚠ Anomaly detected · SYN flood from {ip}',
  '⚠ Brute-force attempt on SSH port 22',
  '⚠ Suspicious payload pattern matched',
  '⚠ Port scan detected from {ip}',
  '⚠ SQL injection signature found in traffic',
  '⚠ ML confidence: ATTACK 98.{r}%',
  '⚠ C2 beacon detected · blocking {ip}',
  '⚠ Lateral movement on VLAN 10',
  '⚠ Known malware hash in packet payload',
  '⚠ DDoS vector from AS{r}',
];

let logFilter = 'all';

function addLog(type, msg) {
  const now = new Date();
  const time = now.toTimeString().slice(0,8);
  const entry = { type, msg, time, ts: Date.now() };
  State.logEntries.unshift(entry);
  if (State.logEntries.length > 120) State.logEntries.pop();
  renderLog();
}

function renderLog() {
  const container = document.getElementById('activityLog');
  if (!container) return;
  const filtered = State.logEntries.filter(e => {
    if (logFilter === 'all')   return true;
    if (logFilter === 'alert') return e.type === 'alert' || e.type === 'warn';
    if (logFilter === 'info')  return e.type === 'info'  || e.type === 'ok';
    return true;
  }).slice(0,40);

  container.innerHTML = '';
  filtered.forEach(e => {
    const div = document.createElement('div');
    div.className = `log-entry ${e.type}`;
    const badgeMap = { info:'INFO', warn:'WARN', alert:'ALERT', ok:'OK' };
    div.innerHTML = `
      <span class="log-time">${e.time}</span>
      <span class="log-badge ${e.type}">${badgeMap[e.type]||'INFO'}</span>
      <span class="log-msg">${e.msg}</span>
    `;
    container.appendChild(div);
  });
}

function tickLog() {
  const r = v => Math.floor(Math.random()*v);
  if (State.isAnomaly) {
    const tmpl = LOG_ATTACKS[r(LOG_ATTACKS.length)];
    const msg = tmpl.replace('{ip}', ATTACKER_IPS()).replace('{r}', r(99));
    addLog(Math.random()<0.6 ? 'alert' : 'warn', msg);
  } else {
    if (Math.random() < 0.85) {
      const tmpl = LOG_NORMALS[r(LOG_NORMALS.length)];
      const msg = tmpl.replace('{r}', r(99)).replace('{p}', PORTS[r(PORTS.length)]);
      addLog(Math.random()<0.7 ? 'ok' : 'info', msg);
    }
  }
}

// Log filter buttons
document.getElementById('filterAll')?.addEventListener('click', () => {
  logFilter = 'all'; setActiveFilter('filterAll'); renderLog();
});
document.getElementById('filterAlert')?.addEventListener('click', () => {
  logFilter = 'alert'; setActiveFilter('filterAlert'); renderLog();
});
document.getElementById('filterInfo')?.addEventListener('click', () => {
  logFilter = 'info'; setActiveFilter('filterInfo'); renderLog();
});

function setActiveFilter(id) {
  ['filterAll','filterAlert','filterInfo'].forEach(i => {
    document.getElementById(i)?.classList.remove('active');
  });
  document.getElementById(id)?.classList.add('active');
}

// ── Connection Table ──────────────────────────────────────────────
function updateConnections() {
  const tbody = document.getElementById('connTableBody');
  if (!tbody) return;

  // Add or remove rows
  const n = State.isAnomaly ? 8+Math.floor(Math.random()*6) : 4+Math.floor(Math.random()*4);
  State.connRows = Array.from({length:n}, () => {
    const isSuspicious = State.isAnomaly && Math.random() < 0.4;
    const isMalicious  = State.isAnomaly && Math.random() < 0.2;
    return {
      src:   ATTACKER_IPS(),
      port:  PORTS[Math.floor(Math.random()*PORTS.length)],
      proto: PROTOCOLS[Math.floor(Math.random()*5)],
      bytes: (Math.floor(Math.random()*9000)+100) + (Math.random()<0.3?'K':'B'),
      status: isMalicious ? 'BLOCKED' : isSuspicious ? 'SUSPECT' : 'ALLOWED',
    };
  });

  const scrollTop = tbody.parentElement.scrollTop;
  tbody.innerHTML = '';
  State.connRows.forEach(r => {
    const tr = document.createElement('tr');
    const statusCls = r.status==='BLOCKED' ? 'status-bad' : r.status==='SUSPECT' ? 'status-sus' : 'status-ok';
    tr.innerHTML = `
      <td class="src-ip">${r.src}</td>
      <td>${r.port}</td>
      <td>${r.proto}</td>
      <td>${r.bytes}</td>
      <td class="${statusCls}">${r.status}</td>
    `;
    tbody.appendChild(tr);
  });

  el('connCount', `${n} active`);
  tbody.parentElement.scrollTop = scrollTop;
}

// ── Geo Map ───────────────────────────────────────────────────────
const GEO_POINTS = [
  { x: 72, y: 42, country:'CN' },
  { x: 55, y: 28, country:'RU' },
  { x: 60, y: 52, country:'IN' },
  { x: 12, y: 48, country:'US' },
  { x: 47, y: 32, country:'DE' },
  { x: 68, y: 60, country:'ID' },
  { x: 20, y: 65, country:'BR' },
  { x: 57, y: 45, country:'IR' },
  { x: 78, y: 36, country:'KP' },
  { x: 52, y: 35, country:'UA' },
];
const DEFENDER = { x: 50, y: 50 };

function initGeoMap() {
  const nodes = document.getElementById('geoNodes');
  if (!nodes) return;

  // Defender node (our server)
  const def = document.createElement('div');
  def.className = 'geo-node defender';
  def.style.left = DEFENDER.x+'%';
  def.style.top  = DEFENDER.y+'%';
  def.title = 'Protected Server';
  nodes.appendChild(def);

  // Attacker nodes
  GEO_POINTS.forEach(p => {
    const n = document.createElement('div');
    n.className = 'geo-node attacker';
    n.style.left = p.x+'%';
    n.style.top  = p.y+'%';
    n.title = p.country;
    n.dataset.country = p.country;
    nodes.appendChild(n);
  });

  el('topOrigin', 'CN/RU');
}

function fireGeoBeam() {
  const pulses = document.getElementById('geoPulses');
  const wrap   = document.getElementById('geoMapWrap');
  if (!pulses || !wrap) return;

  const src = GEO_POINTS[Math.floor(Math.random()*GEO_POINTS.length)];
  const wW  = wrap.offsetWidth;
  const wH  = wrap.offsetHeight;

  const sx = src.x/100 * wW;
  const sy = src.y/100 * wH;
  const dx = DEFENDER.x/100 * wW;
  const dy = DEFENDER.y/100 * wH;

  // Pulse at source
  const pulse = document.createElement('div');
  pulse.className = 'geo-pulse';
  pulse.style.left = src.x+'%';
  pulse.style.top  = src.y+'%';
  pulses.appendChild(pulse);
  setTimeout(() => pulse.remove(), 1500);

  // Beam
  const dx2 = dx - sx, dy2 = dy - sy;
  const len = Math.sqrt(dx2*dx2 + dy2*dy2);
  const angle = Math.atan2(dy2, dx2) * 180 / Math.PI;

  const beam = document.createElement('div');
  beam.className = 'geo-beam';
  beam.style.cssText = `
    left:${sx}px; top:${sy}px;
    width:${len}px;
    transform:rotate(${angle}deg);
  `;
  pulses.appendChild(beam);
  setTimeout(() => beam.remove(), 1500);

  // Update stats
  State.blockedIPSet.add(ATTACKER_IPS());
  el('attackVectors', State.blockedIPSet.size + Math.floor(State.uptime/10));
  el('blockedIPs',    State.blockedIPSet.size);
}

// ── Anomaly Engine ────────────────────────────────────────────────
function triggerAnomaly() {
  if (State.isAnomaly) return;
  State.isAnomaly = true;
  State.alertCount++;
  State.threatsBlocked++;

  const type = ATTACK_TYPES[Math.floor(Math.random()*ATTACK_TYPES.length)];
  const srcIP = ATTACKER_IPS();
  const port  = PORTS[Math.floor(Math.random()*PORTS.length)];
  const conf  = (95+Math.random()*4.9).toFixed(1);

  // Status badge
  const badge = document.getElementById('statusBadge');
  const label = document.getElementById('statusLabel');
  badge?.classList.add('anomaly');
  if (label) label.textContent = '⚠ ATTACK DETECTED';

  // Alert panel
  const panel  = document.getElementById('alertPanel');
  const ring   = document.getElementById('alertRing');
  const aLabel = document.getElementById('alertStateLabel');
  const aSub   = document.getElementById('alertStateSub');
  const aIcon  = document.getElementById('alertIcon');
  const tDets  = document.getElementById('threatDetails');

  panel?.classList.add('anomaly-panel');
  ring?.classList.add('danger');
  aLabel?.classList.add('danger');
  if (aLabel) aLabel.textContent = 'ATTACK DETECTED';
  if (aSub)   aSub.textContent   = `Anomalous traffic pattern identified`;
  if (aIcon)  aIcon.innerHTML = `
    <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" stroke-width="1.5">
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
      <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>`;

  el('threatType', type);
  el('threatSrc',  srcIP);
  el('threatPort', String(port));
  el('threatConf', conf+'%');
  el('alertCountBadge', `${State.alertCount} events`);
  if (tDets) tDets.style.display = 'block';

  // Overlay
  document.getElementById('anomalyOverlay')?.classList.add('active');

  // Toast
  showToast('alert', '⚠ INTRUSION DETECTED', `${type} · from ${srcIP}`);

  // Log
  addLog('alert', `ATTACK: ${type} from ${srcIP} · port ${port} · confidence ${conf}%`);
  addLog('warn',  `ML pipeline classified traffic as MALICIOUS`);

  // Clear after 6–12s
  const duration = 6000 + Math.random()*6000;
  State.anomalyTimeout = setTimeout(clearAnomaly, duration);
}

function clearAnomaly() {
  State.isAnomaly = false;

  const badge = document.getElementById('statusBadge');
  const label = document.getElementById('statusLabel');
  badge?.classList.remove('anomaly');
  if (label) label.textContent = 'LIVE · MONITORING';

  const panel  = document.getElementById('alertPanel');
  const ring   = document.getElementById('alertRing');
  const aLabel = document.getElementById('alertStateLabel');
  const aSub   = document.getElementById('alertStateSub');
  const aIcon  = document.getElementById('alertIcon');
  const tDets  = document.getElementById('threatDetails');

  panel?.classList.remove('anomaly-panel');
  ring?.classList.remove('danger');
  aLabel?.classList.remove('danger');
  if (aLabel) aLabel.textContent = 'SYSTEM SECURE';
  if (aSub)   aSub.textContent   = 'All traffic within normal parameters';
  if (aIcon)  aIcon.innerHTML = `
    <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" stroke-width="1.5">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>`;
  if (tDets) tDets.style.display = 'none';

  document.getElementById('anomalyOverlay')?.classList.remove('active');
  showToast('ok', '✓ THREAT NEUTRALIZED', 'System returned to secure state');
  addLog('ok', 'Threat contained · traffic normalized · signatures updated');
}

// ── Toast System ──────────────────────────────────────────────────
function showToast(type, title, sub) {
  const area  = document.getElementById('toastArea');
  if (!area) return;

  const icons = { alert:'⚠', ok:'✓', info:'ℹ' };
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${icons[type]||'ℹ'}</span>
    <div class="toast-body">
      <div class="toast-title">${title}</div>
      <div class="toast-sub">${sub}</div>
    </div>
  `;
  area.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('fadeOut');
    setTimeout(() => toast.remove(), 350);
  }, 4000);
}

// ── Traffic Chart View Buttons ────────────────────────────────────
document.querySelectorAll('.ctrl-btn[data-view]').forEach(btn => {
  btn.addEventListener('click', function() {
    document.querySelectorAll('.ctrl-btn[data-view]').forEach(b=>b.classList.remove('active'));
    this.classList.add('active');
  });
});

// ── Random Anomaly Scheduler ──────────────────────────────────────
function scheduleAnomaly() {
  // Every 15-40 seconds, fire an anomaly
  const delay = 15000 + Math.random() * 25000;
  setTimeout(() => {
    triggerAnomaly();
    scheduleAnomaly();
  }, delay);
}

// ── Boot Sequence ─────────────────────────────────────────────────
function bootSequence() {
  const logs = [
    ['info', 'AEGIS IDS v3.7.2 booting...'],
    ['info', 'Loading ML models: LSTM + Random Forest + AutoEncoder'],
    ['ok',   'Anomaly detection engine initialized · 97.4% accuracy'],
    ['info', 'Network interface eth0 · promiscuous mode ACTIVE'],
    ['info', 'Signature database loaded · 47,283 rules'],
    ['ok',   'Deep packet inspection engine READY'],
    ['ok',   'Real-time threat feed connected · 12 sources'],
    ['ok',   'All systems nominal · monitoring started'],
  ];
  logs.forEach((l,i) => {
    setTimeout(() => addLog(l[0], l[1]), i*300);
  });
  setTimeout(() => showToast('ok', '✓ AEGIS ONLINE', 'All systems operational · monitoring active'), 2500);
}

// ── Master Tick ───────────────────────────────────────────────────
function masterTick() {
  updateStats();
  updateTrafficChart();
  updateProtoChart();
  updateConnections();
  tickLog();

  // Geo beams more frequent during attack
  if (State.isAnomaly) {
    if (Math.random() < 0.7) fireGeoBeam();
  } else {
    if (Math.random() < 0.25) fireGeoBeam();
  }
}

// ── INIT ──────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startClock();
  initSparklines();
  initTrafficChart();
  initProtoChart();
  initGeoMap();
  bootSequence();

  // Start main simulation
  setTimeout(() => {
    masterTick();
    setInterval(masterTick, 1200);
    scheduleAnomaly();
  }, 1000);

  // Initial geo beams after boot
  setTimeout(() => {
    setInterval(() => {
      if (!State.isAnomaly && Math.random() < 0.4) fireGeoBeam();
    }, 3000);
  }, 3000);

  // Double-click anywhere to manually trigger anomaly (demo shortcut)
  document.addEventListener('dblclick', () => {
    if (!State.isAnomaly) {
      triggerAnomaly();
      showToast('info', 'MANUAL TRIGGER', 'Demo anomaly injected by operator');
    } else {
      clearTimeout(State.anomalyTimeout);
      clearAnomaly();
    }
  });

  showToast('info', 'TIP', 'Double-click anywhere to trigger/clear an anomaly');
});
