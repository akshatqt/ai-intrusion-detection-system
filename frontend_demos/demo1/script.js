/* ─────────────────────────────────────────────
   NEURALGUARD IDS — script.js
   Cyberpunk AI Intrusion Detection Dashboard
───────────────────────────────────────────── */

/* ── STATE ── */
if (localStorage.getItem("loggedIn") !== "true") {
  window.location.href = "../demo2/login.html";
}
const state = {
  packetCount: 0,
  avgSize: 512,
  uniqueIPs: 0,
  threatCount: 0,
  isAttack: false,
  attackType: '',
  logCount: 0,
  logFilter: 'all',
  trafficMode: 'all',
  protocolData: { TCP: 0, UDP: 0, ICMP: 0, HTTP: 0, DNS: 0 },
  mlPackets: 0,
};

const ATTACK_TYPES = [
  { name: 'DDoS ATTACK', meta: 'Volumetric flood detected — 847K pps spike', type: 'alert', src: '192.168.45.%d' },
  { name: 'PORT SCAN', meta: 'Sequential port enumeration — 65535 ports/s', type: 'alert', src: '10.0.%d.%d' },
  { name: 'SQL INJECTION', meta: 'Malformed query payload in HTTP POST body', type: 'alert', src: '172.16.%d.%d' },
  { name: 'BRUTE FORCE', meta: 'SSH login attempt — 2,400 attempts/min', type: 'alert', src: '203.0.113.%d' },
  { name: 'XSS ATTACK', meta: 'Script injection detected in request header', type: 'alert', src: '198.51.100.%d' },
];

const LOG_MESSAGES = {
  info:  [
    'Packet captured — 192.168.1.%d → 10.0.0.1 [TCP SYN]',
    'DNS query resolved — domain: api.internal.net',
    'TLS handshake completed — cipher: AES-256-GCM',
    'Flow established — duration: %dms — %dKB transferred',
    'ML inference complete — classification: NORMAL',
    'Deep packet inspection — HTTP GET /api/v2/metrics',
    'BGP route update — AS%d advertised prefix',
  ],
  warn:  [
    'Unusual traffic spike on port 443 — %d req/s',
    'Geo-anomaly: new source country detected [%s]',
    'Rate limit threshold 80%% reached — IP: 10.0.0.%d',
    'Fragmented packet detected — reassembly timeout',
    'Certificate expiry warning — CN: internal.corp',
  ],
  block: [
    'IP BLOCKED: 192.168.%d.%d — reputation score: 12',
    'Firewall rule triggered — DROP chain — port 22',
    'Tor exit node blocked — exit relay detected',
    'Blacklisted ASN — autonomous system: AS%d',
    'Payload signature matched — rule: ET-EXPLOIT-%d',
  ],
  alert: [
    'ANOMALY: Traffic entropy spike — σ=%d.%d',
    'CRITICAL: C2 beacon pattern detected — interval: %ds',
    'ATTACK: %s flooding detected from %d sources',
    'INTRUSION: Lateral movement — 10.0.0.%d → 10.0.0.%d',
    'THREAT: Data exfiltration attempt — %d MB outbound',
  ]
};

const COUNTRIES = ['RU', 'CN', 'KP', 'IR', 'UA', 'BR', 'NG'];

/* ── CLOCK ── */
function updateClock() {
  const now = new Date();
  const hh = String(now.getHours()).padStart(2,'0');
  const mm = String(now.getMinutes()).padStart(2,'0');
  const ss = String(now.getSeconds()).padStart(2,'0');
  document.getElementById('headerTime').textContent = `${hh}:${mm}:${ss}`;
  const days = ['SUN','MON','TUE','WED','THU','FRI','SAT'];
  const months = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'];
  document.getElementById('headerDate').textContent =
    `${days[now.getDay()]} ${String(now.getDate()).padStart(2,'0')} ${months[now.getMonth()]} ${now.getFullYear()}`;
}
setInterval(updateClock, 1000);
updateClock();

/* ── PARTICLE CANVAS ── */
const pCanvas = document.getElementById('particleCanvas');
const pCtx = pCanvas.getContext('2d');
let particles = [];

function resizeParticleCanvas() {
  pCanvas.width = window.innerWidth;
  pCanvas.height = window.innerHeight;
}
resizeParticleCanvas();
window.addEventListener('resize', resizeParticleCanvas);

for (let i = 0; i < 60; i++) {
  particles.push({
    x: Math.random() * window.innerWidth,
    y: Math.random() * window.innerHeight,
    vx: (Math.random() - 0.5) * 0.3,
    vy: (Math.random() - 0.5) * 0.3,
    r: Math.random() * 1.5 + 0.5,
    alpha: Math.random() * 0.5 + 0.1,
    color: Math.random() > 0.5 ? '0,255,231' : '61,139,255',
  });
}

function animateParticles() {
  pCtx.clearRect(0, 0, pCanvas.width, pCanvas.height);
  particles.forEach(p => {
    p.x += p.vx; p.y += p.vy;
    if (p.x < 0) p.x = pCanvas.width;
    if (p.x > pCanvas.width) p.x = 0;
    if (p.y < 0) p.y = pCanvas.height;
    if (p.y > pCanvas.height) p.y = 0;
    pCtx.beginPath();
    pCtx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
    pCtx.fillStyle = `rgba(${p.color}, ${p.alpha})`;
    pCtx.fill();
  });
  // Draw connections
  for (let i = 0; i < particles.length; i++) {
    for (let j = i + 1; j < particles.length; j++) {
      const dx = particles[i].x - particles[j].x;
      const dy = particles[i].y - particles[j].y;
      const dist = Math.sqrt(dx*dx + dy*dy);
      if (dist < 120) {
        pCtx.beginPath();
        pCtx.moveTo(particles[i].x, particles[i].y);
        pCtx.lineTo(particles[j].x, particles[j].y);
        pCtx.strokeStyle = `rgba(0,255,231,${0.08 * (1 - dist/120)})`;
        pCtx.lineWidth = 0.5;
        pCtx.stroke();
      }
    }
  }
  requestAnimationFrame(animateParticles);
}
animateParticles();

/* ── CHARTS ── */
const chartDefaults = {
  responsive: true, maintainAspectRatio: false,
  animation: { duration: 0 },
  plugins: { legend: { display: false }, tooltip: { enabled: false } },
  scales: {
    x: { display: false },
    y: { display: false },
  },
};

// Sparklines
function makeSparkline(id, color) {
  return new Chart(document.getElementById(id), {
    type: 'line',
    data: {
      labels: Array(20).fill(''),
      datasets: [{ data: Array(20).fill(0), borderColor: color, borderWidth: 1.5,
        fill: true, backgroundColor: color.replace('1)', '0.1)'),
        tension: 0.4, pointRadius: 0 }]
    },
    options: { ...chartDefaults }
  });
}

const sparkPackets = makeSparkline('sparkPackets', 'rgba(0,255,231,1)');
const sparkSize    = makeSparkline('sparkSize',    'rgba(61,139,255,1)');
const sparkIPs     = makeSparkline('sparkIPs',     'rgba(180,77,255,1)');
const sparkThreats = makeSparkline('sparkThreats', 'rgba(255,61,113,1)');

function updateSparkline(chart, newVal) {
  chart.data.datasets[0].data.push(newVal);
  chart.data.datasets[0].data.shift();
  chart.update('none');
}

// Main traffic chart
const trafficLabels = Array(60).fill('');
const trafficChart = new Chart(document.getElementById('trafficChart'), {
  type: 'line',
  data: {
    labels: trafficLabels,
    datasets: [
      {
        label: 'Inbound', data: Array(60).fill(0),
        borderColor: '#00ffe7', borderWidth: 2,
        fill: true, backgroundColor: 'rgba(0,255,231,0.06)',
        tension: 0.4, pointRadius: 0,
      },
      {
        label: 'Outbound', data: Array(60).fill(0),
        borderColor: '#3d8bff', borderWidth: 2,
        fill: true, backgroundColor: 'rgba(61,139,255,0.06)',
        tension: 0.4, pointRadius: 0,
      },
      {
        label: 'Blocked', data: Array(60).fill(0),
        borderColor: '#ff3d71', borderWidth: 1.5,
        fill: true, backgroundColor: 'rgba(255,61,113,0.05)',
        tension: 0.4, pointRadius: 0,
      },
    ]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    animation: { duration: 200 },
    plugins: { legend: { display: false } },
    scales: {
      x: { display: false },
      y: {
        display: true, min: 0,
        grid: { color: 'rgba(0,255,231,0.05)', drawBorder: false },
        ticks: { color: 'rgba(200,224,244,0.3)', font: { family: 'Share Tech Mono', size: 9 }, maxTicksLimit: 5 },
      }
    },
    interaction: { intersect: false, mode: 'index' },
  }
});

// Protocol donut chart
const protocolChart = new Chart(document.getElementById('protocolChart'), {
  type: 'doughnut',
  data: {
    labels: ['TCP','UDP','ICMP','HTTP','DNS'],
    datasets: [{
      data: [40, 25, 10, 15, 10],
      backgroundColor: ['rgba(0,255,231,0.8)','rgba(61,139,255,0.8)','rgba(180,77,255,0.8)','rgba(255,61,113,0.8)','rgba(255,214,0,0.8)'],
      borderColor: 'rgba(4,13,24,0)',
      borderWidth: 2, hoverOffset: 6,
    }]
  },
  options: {
    responsive: false, maintainAspectRatio: false,
    animation: { duration: 800 },
    plugins: {
      legend: { display: false },
      tooltip: {
        callbacks: {
          label: (ctx) => ` ${ctx.label}: ${ctx.parsed}%`,
        },
        backgroundColor: 'rgba(6,20,36,0.9)',
        borderColor: 'rgba(0,255,231,0.2)', borderWidth: 1,
        titleFont: { family: 'Orbitron' }, bodyFont: { family: 'Share Tech Mono' },
      }
    },
    cutout: '70%',
  }
});

/* ── UI UPDATERS ── */
function fmt(n) {
  if (n >= 1e6) return (n/1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n/1e3).toFixed(1) + 'K';
  return String(n);
}

function updateStats() {
  const mult = state.isAttack ? 4 : 1;
  const pktDelta = Math.floor(Math.random() * 500 * mult + 200);
  state.packetCount += pktDelta;
  state.mlPackets += pktDelta;
  state.avgSize = Math.floor(512 + (Math.random() - 0.5) * 80 * mult);
  if (Math.random() < 0.3) state.uniqueIPs += Math.floor(Math.random() * 3 * mult + 1);

  document.getElementById('packetCount').textContent = fmt(state.packetCount);
  document.getElementById('avgSize').textContent = state.avgSize;
  document.getElementById('uniqueIPs').textContent = state.uniqueIPs;
  document.getElementById('threatCount').textContent = state.threatCount;

  document.getElementById('packetDelta').textContent = `+${fmt(pktDelta)}/s`;
  document.getElementById('sizeDelta').textContent = `±${Math.floor(Math.random()*30)}B`;
  document.getElementById('ipDelta').textContent = `+${Math.floor(Math.random()*3)} new`;
  document.getElementById('threatDelta').textContent = `${Math.floor(state.threatCount * 0.2)} critical`;

  document.getElementById('mlPackets').textContent = fmt(state.mlPackets);
  document.getElementById('inferenceTime').textContent = (1.8 + Math.random() * 1.2).toFixed(1) + 'ms';

  // Sparklines
  updateSparkline(sparkPackets, pktDelta);
  updateSparkline(sparkSize, state.avgSize);
  updateSparkline(sparkIPs, state.uniqueIPs % 100);
  updateSparkline(sparkThreats, state.threatCount % 50);
}

function updateTrafficChart() {
  const mult = state.isAttack ? 4 : 1;
  const inbound  = Math.floor(Math.random() * 800 * mult + 100);
  const outbound = Math.floor(Math.random() * 500 + 50);
  const blocked  = state.isAttack ? Math.floor(Math.random() * 300 + 50) : Math.floor(Math.random() * 30);

  [trafficChart.data.datasets[0].data, trafficChart.data.datasets[1].data,
   trafficChart.data.datasets[2].data].forEach(arr => arr.shift());

  trafficChart.data.datasets[0].data.push(inbound);
  trafficChart.data.datasets[1].data.push(outbound);
  trafficChart.data.datasets[2].data.push(blocked);
  trafficChart.update('none');

  // Update donut total
  const total = state.packetCount;
  document.getElementById('donutTotal').textContent = fmt(total);

  // Update protocol percentages
  protocolChart.data.datasets[0].data = [
    40 + Math.floor(Math.random()*10),
    20 + Math.floor(Math.random()*10),
    5  + Math.floor(Math.random()*8),
    15 + Math.floor(Math.random()*5),
    8  + Math.floor(Math.random()*5),
  ];
  protocolChart.update('none');
}

/* ── ANOMALY SYSTEM ── */
function setNormal() {
  state.isAttack = false;
  const panel = document.getElementById('anomalyPanel');
  panel.className = 'panel anomaly-panel normal';

  const dot = document.getElementById('anomalyDot');
  dot.className = 'as-dot';
  dot.style.background = 'var(--cyan)';
  dot.style.boxShadow = '0 0 8px var(--cyan)';

  document.getElementById('anomalyLabel').textContent = 'SYSTEM NORMAL';
  document.getElementById('anomalyLabel').style.color = 'var(--cyan)';
  document.getElementById('anomalyType').textContent = 'NO ACTIVE THREATS';
  document.getElementById('anomalyMeta').textContent = 'All traffic within expected parameters';
  document.getElementById('anomalyActions').style.display = 'none';

  const bar = document.getElementById('aiConfidenceBar');
  bar.style.width = (96 + Math.random()*3).toFixed(1) + '%';
  bar.style.background = 'linear-gradient(90deg, var(--cyan), #00c9a7)';
  bar.style.boxShadow = '0 0 8px var(--cyan)';
  document.getElementById('aiConfidencePct').textContent = (96 + Math.random()*3).toFixed(1) + '%';
  document.getElementById('aiConfidencePct').style.color = 'var(--cyan)';

  const statusDot = document.querySelector('.status-dot');
  statusDot.className = 'status-dot pulse-green';
  document.querySelector('.status-label').textContent = 'LIVE · MONITORING';
  document.querySelector('.status-label').parentElement.style.color = 'var(--cyan)';

  setThreatLevel(1);
  updateMLClasses(false, '');
}

function setAttack(atk) {
  state.isAttack = true;
  state.attackType = atk.name;
  state.threatCount++;

  const panel = document.getElementById('anomalyPanel');
  panel.className = 'panel anomaly-panel attack';

  const dot = document.getElementById('anomalyDot');
  dot.style.background = 'var(--red)';
  dot.style.boxShadow = '0 0 8px var(--red)';

  document.getElementById('anomalyLabel').textContent = '⚠ THREAT DETECTED';
  document.getElementById('anomalyLabel').style.color = 'var(--red)';
  document.getElementById('anomalyType').textContent = atk.name;
  document.getElementById('anomalyMeta').textContent = atk.meta;
  document.getElementById('anomalyActions').style.display = 'flex';

  const confidence = (88 + Math.random()*10).toFixed(1);
  const bar = document.getElementById('aiConfidenceBar');
  bar.style.width = confidence + '%';
  bar.style.background = 'linear-gradient(90deg, var(--red), #cc0033)';
  bar.style.boxShadow = '0 0 8px var(--red)';
  document.getElementById('aiConfidencePct').textContent = confidence + '%';
  document.getElementById('aiConfidencePct').style.color = 'var(--red)';

  const statusDot = document.querySelector('.status-dot');
  statusDot.className = 'status-dot pulse-red';
  document.querySelector('.status-label').textContent = 'LIVE · UNDER ATTACK';
  document.querySelector('.status-label').parentElement.style.color = 'var(--red)';

  setThreatLevel(Math.floor(Math.random()*2)+4); // 4 or 5
  updateMLClasses(true, atk.name);

  addLog(atk.type, `DETECTED: ${atk.name} — ${atk.meta}`);
}

function setThreatLevel(lvl) {
  const segs = document.querySelectorAll('.tl-seg');
  const labels = ['', 'LOW', 'GUARDED', 'ELEVATED', 'HIGH', 'CRITICAL'];
  const colors = ['', 'var(--cyan)', 'var(--blue)', 'var(--yellow)', 'var(--orange)', 'var(--red)'];
  segs.forEach((s,i) => {
    s.classList.remove('active');
    if (i < lvl) s.classList.add('active');
  });
  document.getElementById('threatLevelText').textContent = labels[lvl] || 'LOW';
  document.getElementById('threatLevelText').style.color = colors[lvl] || 'var(--cyan)';
}

function updateMLClasses(isAttack, name) {
  if (!isAttack) {
    document.getElementById('pctDdos').textContent = '0%';
    document.getElementById('pctScan').textContent = '0%';
    document.getElementById('pctSql').textContent = '0%';
    document.getElementById('pctBrute').textContent = '0%';
    document.getElementById('pctNormal').textContent = '100%';
    return;
  }
  const pcts = { ddos:0, scan:0, sql:0, brute:0 };
  const mainPct = 70 + Math.floor(Math.random()*20);
  if (name.includes('DDoS')) pcts.ddos = mainPct;
  else if (name.includes('PORT')) pcts.scan = mainPct;
  else if (name.includes('SQL') || name.includes('XSS')) pcts.sql = mainPct;
  else if (name.includes('BRUTE')) pcts.brute = mainPct;
  const normal = Math.max(0, 100 - mainPct - 5);
  document.getElementById('pctDdos').textContent = pcts.ddos + '%';
  document.getElementById('pctScan').textContent = pcts.scan + '%';
  document.getElementById('pctSql').textContent = pcts.sql + '%';
  document.getElementById('pctBrute').textContent = pcts.brute + '%';
  document.getElementById('pctNormal').textContent = normal + '%';
}

/* ── ACTIVITY LOG ── */
let allLogs = [];

function r(n) { return Math.floor(Math.random()*n); }
function pick(arr) { return arr[r(arr.length)]; }
function fillTemplate(tpl) {
  return tpl.replace(/%d/g, () => r(256)).replace(/%s/g, () => pick(COUNTRIES));
}

function addLog(type, msg) {
  const now = new Date();
  const ts = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`;
  allLogs.unshift({ ts, type, msg: msg || fillTemplate(pick(LOG_MESSAGES[type])) });
  if (allLogs.length > 200) allLogs.pop();
  state.logCount++;
  document.getElementById('logCounter').textContent = `${state.logCount} EVENTS`;
  renderLogs();
}

function renderLogs() {
  const body = document.getElementById('logBody');
  const filter = state.logFilter;
  const visible = filter === 'all' ? allLogs : allLogs.filter(l => l.type === filter);
  body.innerHTML = visible.slice(0,80).map(l => `
    <div class="log-entry type-${l.type}">
      <span class="log-time">${l.ts}</span>
      <span class="log-type type-${l.type}">${l.type.toUpperCase()}</span>
      <span class="log-msg" title="${l.msg}">${l.msg}</span>
    </div>
  `).join('');
}

window.filterLogs = (f) => {
  state.logFilter = f;
  document.querySelectorAll('.log-filter').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.log-filter').forEach(b => {
    if (b.textContent.toLowerCase() === f || (f==='all' && b.textContent==='ALL')) b.classList.add('active');
  });
  renderLogs();
};

/* ── GEO MAP ATTACKS ── */
// Fixed geo nodes (x,y in SVG coords 0-900, 0-450)
const geoNodes = [
  { x: 135, y: 155, name: 'US-EAST',    color: '#00ffe7', type: 'protected' },
  { x:  85, y: 130, name: 'US-WEST',    color: '#00ffe7', type: 'protected' },
  { x: 430, y:  80, name: 'EU-CENTRAL', color: '#00ffe7', type: 'protected' },
  { x: 680, y: 100, name: 'APAC',       color: '#00ffe7', type: 'protected' },
  { x: 500, y:  85, name: 'RUSSIA',     color: '#ff3d71', type: 'attack' },
  { x: 620, y: 110, name: 'CHINA',      color: '#ff3d71', type: 'attack' },
  { x: 390, y: 165, name: 'AFRICA',     color: '#ffd600', type: 'suspicious' },
  { x: 190, y: 310, name: 'S.AMERICA',  color: '#ffd600', type: 'suspicious' },
];

let activeAttackers = 0;

function renderGeoBase() {
  const pings = document.getElementById('attackPings');
  pings.innerHTML = '';
  geoNodes.forEach(n => {
    const c = document.createElementNS('http://www.w3.org/2000/svg','circle');
    c.setAttribute('cx', n.x); c.setAttribute('cy', n.y); c.setAttribute('r', '4');
    c.setAttribute('fill', n.color); c.setAttribute('opacity', '0.9');
    if (n.type === 'protected') {
      c.setAttribute('filter', `drop-shadow(0 0 4px ${n.color})`);
    }
    pings.appendChild(c);

    // Pulse rings for protected nodes
    if (n.type === 'protected') {
      for (let i = 0; i < 2; i++) {
        const ring = document.createElementNS('http://www.w3.org/2000/svg','circle');
        ring.setAttribute('cx', n.x); ring.setAttribute('cy', n.y); ring.setAttribute('r', '4');
        ring.setAttribute('fill', 'none'); ring.setAttribute('stroke', n.color);
        ring.setAttribute('stroke-width', '1');
        ring.style.animation = `geoRing ${1.5 + i*0.7}s ease-out infinite`;
        ring.style.animationDelay = `${i*0.6}s`;
        pings.appendChild(ring);
      }
    }
  });
}

// Inject keyframe for geo rings
const geoStyle = document.createElement('style');
geoStyle.textContent = `
@keyframes geoRing {
  0%   { r: 4; opacity: 0.8; }
  100% { r: 22; opacity: 0; }
}
`;
document.head.appendChild(geoStyle);

function addAttackLine() {
  if (!state.isAttack) return;
  const attackSrcs = geoNodes.filter(n => n.type === 'attack' || n.type === 'suspicious');
  const defenders  = geoNodes.filter(n => n.type === 'protected');
  const src = pick(attackSrcs);
  const dst = pick(defenders);

  const lines = document.getElementById('attackLines');
  const line = document.createElementNS('http://www.w3.org/2000/svg','line');
  line.setAttribute('x1', src.x); line.setAttribute('y1', src.y);
  line.setAttribute('x2', dst.x); line.setAttribute('y2', dst.y);
  line.setAttribute('stroke', src.color);
  line.setAttribute('stroke-width', '1');
  line.setAttribute('opacity', '0.6');
  line.setAttribute('stroke-dasharray', '5 3');
  line.style.animation = 'fadeAttackLine 2s ease-out forwards';
  lines.appendChild(line);
  setTimeout(() => lines.removeChild(line), 2000);

  activeAttackers = Math.min(attackSrcs.length, activeAttackers + 1);
  document.getElementById('activeAttackers').textContent = `${activeAttackers} ACTIVE`;
}

const geoLineStyle = document.createElement('style');
geoLineStyle.textContent = `
@keyframes fadeAttackLine {
  0%   { opacity: 0.8; stroke-dashoffset: 30; }
  60%  { opacity: 0.6; }
  100% { opacity: 0; }
}
`;
document.head.appendChild(geoLineStyle);

//renderGeoBase();

/* ── CHART MODE ── */
window.setChartMode = (mode) => {
  state.trafficMode = mode;
  document.querySelectorAll('.ctrl-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.ctrl-btn').forEach(b => {
    if (b.textContent === mode.toUpperCase()) b.classList.add('active');
  });
};

/* ── MAIN SIMULATION LOOP ── */
let attackTimer = null;
let normalTimer = null;

function triggerAttack() {
  const atk = pick(ATTACK_TYPES);
  setAttack(atk);
  addLog('alert', `ATTACK INITIATED: ${atk.name}`);
  addLog('block', null);

  activeAttackers = 0;
  document.getElementById('activeAttackers').textContent = `0 ACTIVE`;

  const duration = 8000 + r(12000); // 8-20 seconds
  normalTimer = setTimeout(() => {
    setNormal();
    activeAttackers = 0;
    document.getElementById('activeAttackers').textContent = `0 ACTIVE`;
    addLog('info', 'Attack mitigated — system returned to normal state');
    scheduleNextAttack();
  }, duration);
}

function scheduleNextAttack() {
  const delay = 15000 + r(20000); // 15-35 seconds
  attackTimer = setTimeout(triggerAttack, delay);
}

// Initial logs
['info','info','info','warn','info','block'].forEach(t => addLog(t, null));

// Start simulation
setNormal();
scheduleNextAttack();

// Ticker intervals
setInterval(updateStats, 1000);
setInterval(updateTrafficChart, 800);
setInterval(() => {
  const types = ['info','info','info','warn'];
  if (state.isAttack) types.push('alert','block');
  addLog(pick(types), null);
}, 2500);

setInterval(() => {
  if (state.isAttack) addAttackLine();
}, 600);
// 🌍 Initialize world map
document.addEventListener("DOMContentLoaded", function () {

   var map = L.map('map').setView([20, 0], 2);

  map.attributionControl.setPrefix(false);

  /*L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: ''
  }).addTo(map); */
 L.tileLayer('https://tiles.stadiamaps.com/tiles/alidade_smooth/{z}/{x}/{y}{r}.png', {
    attribution: ''
}).addTo(map);
//L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {

    var attacks = [
        {lat: 28.6, lng: 77.2},
        {lat: 37.7, lng: -122.4},
        {lat: 51.5, lng: -0.1}
    ];

    attacks.forEach(loc => {
        L.circleMarker([loc.lat, loc.lng], {
            color: '#00ffe7',
            radius: 6,
            className: 'attack-marker'
        }).addTo(map);
    });

});