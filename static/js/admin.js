// OAuth2 Admin Dashboard — Alpine.js SPA
// Requires: Alpine.js v3, Chart.js v4, Tailwind CSS

// ─── Constants ───────────────────────────────────────────────────────────────

const PAGE_ROUTES = {
  '':         'dashboard',
  'dashboard':'dashboard',
  'clients':  'clients',
  'tokens':   'tokens',
  'users':    'users',
  'device':   'device',
  'keys':     'keys',
  'metrics':  'metrics',
  'events':   'events',
};

// ─── Utility helpers ──────────────────────────────────────────────────────────

function escapeHtml(str) {
  if (str == null) return '';
  const d = document.createElement('div');
  d.textContent = String(str);
  return d.innerHTML;
}

function formatDate(dateStr) {
  if (!dateStr) return '—';
  try { return new Date(dateStr).toLocaleString(); } catch (_) { return dateStr; }
}

function relativeTime(dateStr) {
  if (!dateStr) return '—';
  const diff = Date.now() - new Date(dateStr).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function debounce(fn, ms = 300) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

// ─── Prometheus text-format parser ───────────────────────────────────────────

const _prometheusCache = { raw: null, ts: 0 };

async function fetchPrometheus() {
  // Memoize for 15 seconds.
  if (Date.now() - _prometheusCache.ts < 15000 && _prometheusCache.raw) {
    return _prometheusCache.raw;
  }
  try {
    const res = await fetch('/metrics');
    if (!res.ok) return {};
    const text = await res.text();
    _prometheusCache.raw = parsePrometheus(text);
    _prometheusCache.ts = Date.now();
    return _prometheusCache.raw;
  } catch (_) { return {}; }
}

function parsePrometheus(text) {
  const out = {};
  for (const line of text.split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const spaceIdx = line.lastIndexOf(' ');
    if (spaceIdx < 0) continue;
    const metricPart = line.slice(0, spaceIdx).trim();
    const val = parseFloat(line.slice(spaceIdx + 1));
    // e.g. oauth2_server_oauth_token_issued_total or
    //      oauth2_server_http_requests_total{method="GET",status="200"}
    const braceIdx = metricPart.indexOf('{');
    const name = braceIdx >= 0 ? metricPart.slice(0, braceIdx) : metricPart;
    const labels = {};
    if (braceIdx >= 0) {
      const labelStr = metricPart.slice(braceIdx + 1, metricPart.lastIndexOf('}'));
      for (const pair of labelStr.split(',')) {
        const [k, v] = pair.split('=');
        if (k && v) labels[k.trim()] = v.replace(/"/g, '').trim();
      }
    }
    if (!out[name]) out[name] = [];
    out[name].push({ labels, value: val });
  }
  return out;
}

function prometheusScalar(metrics, name) {
  const series = metrics[name];
  if (!series || !series.length) return 0;
  return series.reduce((sum, e) => sum + e.value, 0);
}

function prometheusLabeled(metrics, name, label, value) {
  const series = metrics[name];
  if (!series) return 0;
  const match = series.find(e => e.labels[label] === value);
  return match ? match.value : 0;
}

// Compute quantile from a Prometheus histogram's cumulative `_bucket{le="…"}` series.
// Works with default `prometheus` crate histograms which only emit buckets (not quantiles).
// q in [0,1]. Returns value in the histogram's native unit (seconds for durations).
function histogramQuantile(metrics, baseName, q) {
  const buckets = metrics[baseName + '_bucket'];
  if (!buckets || !buckets.length) return 0;
  const parsed = buckets
    .map(b => ({
      le: b.labels.le === '+Inf' ? Infinity : parseFloat(b.labels.le),
      count: b.value,
    }))
    .filter(b => !isNaN(b.le))
    .sort((a, b) => a.le - b.le);
  if (!parsed.length) return 0;
  const total = parsed[parsed.length - 1].count;
  if (total <= 0) return 0;
  const target = q * total;
  let prevLe = 0, prevCount = 0;
  for (const { le, count } of parsed) {
    if (count >= target) {
      if (le === Infinity) return prevLe;
      if (count === prevCount) return le;
      const frac = (target - prevCount) / (count - prevCount);
      return prevLe + frac * (le - prevLe);
    }
    prevLe = le;
    prevCount = count;
  }
  return prevLe;
}

// In-memory trend buffers for sparklines (last ~20 polls per metric).
const _trendHistory = {};
function pushTrend(key, value, max = 20) {
  if (!_trendHistory[key]) _trendHistory[key] = [];
  _trendHistory[key].push(value);
  if (_trendHistory[key].length > max) _trendHistory[key].shift();
  return _trendHistory[key];
}
function trendDelta(key) {
  const h = _trendHistory[key];
  if (!h || h.length < 2) return null;
  return h[h.length - 1] - h[h.length - 2];
}
// Build a compact sparkline SVG path from a numeric series.
function sparklinePath(series, w = 80, h = 24) {
  if (!series || series.length < 2) return '';
  const min = Math.min(...series);
  const max = Math.max(...series);
  const range = max - min || 1;
  const step = w / (series.length - 1);
  return series
    .map((v, i) => {
      const x = (i * step).toFixed(1);
      const y = (h - ((v - min) / range) * h).toFixed(1);
      return `${i === 0 ? 'M' : 'L'}${x},${y}`;
    })
    .join(' ');
}

// ─── Chart helpers ────────────────────────────────────────────────────────────

const _charts = {};

function createOrUpdateChart(id, config) {
  if (_charts[id]) {
    Object.assign(_charts[id].data, config.data);
    _charts[id].update('none');
    return _charts[id];
  }
  const ctx = document.getElementById(id);
  if (!ctx) return null;
  _charts[id] = new Chart(ctx, config);
  return _charts[id];
}

function chartDefaults() {
  const dark = document.documentElement.classList.contains('dark');
  return {
    gridColor: dark ? 'rgba(148,163,184,0.08)' : 'rgba(148,163,184,0.18)',
    textColor: dark ? '#94a3b8' : '#64748b',
    bg: dark ? '#0f172a' : '#ffffff',
    tooltipBg: dark ? 'rgba(15,23,42,0.95)' : 'rgba(255,255,255,0.98)',
    tooltipBorder: dark ? 'rgba(148,163,184,0.2)' : 'rgba(148,163,184,0.3)',
    tooltipText: dark ? '#e2e8f0' : '#0f172a',
  };
}

// Shared palette — modern engineering-dashboard tone.
const PALETTE = {
  indigo:  '#6366f1',
  emerald: '#10b981',
  rose:    '#f43f5e',
  amber:   '#f59e0b',
  cyan:    '#06b6d4',
  violet:  '#a855f7',
  slate:   '#64748b',
};

function baseChartOpts() {
  const { textColor, gridColor, tooltipBg, tooltipBorder, tooltipText } = chartDefaults();
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 400, easing: 'easeOutQuart' },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: tooltipBg,
        borderColor: tooltipBorder,
        borderWidth: 1,
        titleColor: tooltipText,
        bodyColor: tooltipText,
        padding: 10,
        cornerRadius: 6,
        displayColors: true,
        titleFont: { family: "'Manrope', system-ui, sans-serif", weight: '600', size: 12 },
        bodyFont:  { family: "'JetBrains Mono', monospace", size: 11 },
      },
    },
    scales: {
      x: {
        ticks: { color: textColor, font: { family: "'Manrope', system-ui, sans-serif", size: 11 } },
        grid: { color: gridColor, drawBorder: false },
      },
      y: {
        beginAtZero: true,
        ticks: { color: textColor, font: { family: "'JetBrains Mono', monospace", size: 10 } },
        grid: { color: gridColor, drawBorder: false },
      },
    },
  };
}

// ─── Alpine stores ────────────────────────────────────────────────────────────

document.addEventListener('alpine:init', () => {

  Alpine.store('theme', {
    isDark: false,
    init() {
      const saved = localStorage.getItem('oauth2-admin-theme');
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      this.isDark = saved === 'dark' || (!saved && prefersDark);
      this._apply();
    },
    toggle() {
      this.isDark = !this.isDark;
      localStorage.setItem('oauth2-admin-theme', this.isDark ? 'dark' : 'light');
      this._apply();
    },
    _apply() {
      if (this.isDark) document.documentElement.classList.add('dark');
      else document.documentElement.classList.remove('dark');
    },
  });

  Alpine.store('router', {
    page: 'dashboard',
    sidebarOpen: false,
    showRotateModal: false,
    init() {
      const path = window.location.pathname.replace('/admin', '').replace(/^\//, '');
      this.page = PAGE_ROUTES[path] || 'dashboard';
      window.addEventListener('popstate', () => {
        const p = window.location.pathname.replace('/admin', '').replace(/^\//, '');
        this.page = PAGE_ROUTES[p] || 'dashboard';
      });
    },
    navigate(page) {
      this.page = page;
      this.sidebarOpen = false;
      const url = page === 'dashboard' ? '/admin' : `/admin/${page}`;
      history.pushState({ page }, '', url);
    },
  });

  Alpine.store('caps', {
    events: true,
    device_flow: true,
    key_rotation: true,
    async init() {
      try {
        const res = await fetch('/admin/api/capabilities');
        if (res.ok) Object.assign(this, await res.json());
      } catch (_) {}
    },
  });
});

// ─── Page: Dashboard ─────────────────────────────────────────────────────────

function dashboardPage() {
  return {
    stats: null,
    loading: true,
    chartInterval: null,

    async init() {
      await this.load();
      await this.initCharts();
      this.chartInterval = setInterval(() => this.refreshCharts(), 30000);
    },

    destroy() {
      if (this.chartInterval) clearInterval(this.chartInterval);
    },

    async load() {
      this.loading = true;
      try {
        const res = await fetch('/admin/api/dashboard');
        this.stats = await res.json();
      } catch (_) {}
      this.loading = false;
    },

    async initCharts() {
      const m = await fetchPrometheus();
      const opts = baseChartOpts();

      // Token issued/revoked
      const issued  = prometheusScalar(m, 'oauth2_server_oauth_token_issued_total');
      const revoked = prometheusScalar(m, 'oauth2_server_oauth_token_revoked_total');
      createOrUpdateChart('tokenChart', {
        type: 'bar',
        data: {
          labels: ['Issued', 'Revoked'],
          datasets: [{
            data: [issued, revoked],
            backgroundColor: [PALETTE.indigo, PALETTE.rose],
            borderRadius: 6, borderSkipped: false, barThickness: 36,
          }],
        },
        options: opts,
      });

      // HTTP status distribution
      const s2xx = prometheusLabeled(m, 'oauth2_server_http_requests_total', 'status_class', '2xx')
        || prometheusScalar(m, 'oauth2_server_http_requests_total');
      const s4xx = prometheusLabeled(m, 'oauth2_server_http_requests_total', 'status_class', '4xx');
      const s5xx = prometheusLabeled(m, 'oauth2_server_http_requests_total', 'status_class', '5xx');
      createOrUpdateChart('requestChart', {
        type: 'doughnut',
        data: {
          labels: ['2xx Success', '4xx Client', '5xx Server'],
          datasets: [{
            data: [s2xx, s4xx, s5xx],
            backgroundColor: [PALETTE.emerald, PALETTE.amber, PALETTE.rose],
            borderWidth: 0, hoverOffset: 6,
          }],
        },
        options: {
          ...opts,
          cutout: '66%',
          plugins: {
            ...opts.plugins,
            legend: {
              display: true,
              position: 'bottom',
              labels: {
                color: chartDefaults().textColor,
                font: { family: "'Manrope', system-ui, sans-serif", size: 11 },
                boxWidth: 10, boxHeight: 10, padding: 14, usePointStyle: true,
              },
            },
          },
          scales: {},
        },
      });

      // Latency p50/p95/p99 — computed from histogram buckets.
      const p50 = histogramQuantile(m, 'oauth2_server_http_request_duration_seconds', 0.5)  * 1000;
      const p95 = histogramQuantile(m, 'oauth2_server_http_request_duration_seconds', 0.95) * 1000;
      const p99 = histogramQuantile(m, 'oauth2_server_http_request_duration_seconds', 0.99) * 1000;
      pushTrend('p95', p95);
      createOrUpdateChart('latencyChart', {
        type: 'bar',
        data: {
          labels: ['p50', 'p95', 'p99'],
          datasets: [{
            label: 'latency (ms)',
            data: [p50.toFixed(1), p95.toFixed(1), p99.toFixed(1)],
            backgroundColor: [PALETTE.cyan, PALETTE.indigo, PALETTE.violet],
            borderRadius: 6, borderSkipped: false, barThickness: 34,
          }],
        },
        options: {
          ...opts,
          indexAxis: 'y',
          scales: {
            x: { ...opts.scales.x, title: { display: true, text: 'ms', color: chartDefaults().textColor, font: { size: 10 } } },
            y: opts.scales.y,
          },
        },
      });

      // Resilience events
      const rl = prometheusScalar(m, 'oauth2_server_rate_limit_rejected_total');
      const cb = prometheusScalar(m, 'oauth2_server_circuit_breaker_trips_total');
      const bp = prometheusScalar(m, 'oauth2_server_back_pressure_rejected_total');
      createOrUpdateChart('resilienceChart', {
        type: 'bar',
        data: {
          labels: ['Rate-limit', 'Circuit trips', 'Back-pressure'],
          datasets: [{
            data: [rl, cb, bp],
            backgroundColor: [PALETTE.amber, PALETTE.rose, PALETTE.violet],
            borderRadius: 6, borderSkipped: false, barThickness: 34,
          }],
        },
        options: opts,
      });
    },

    async refreshCharts() {
      _prometheusCache.ts = 0; // force refresh
      await this.initCharts();
    },
  };
}

// ─── Shared grid factory ──────────────────────────────────────────────────────

function makeGrid(endpoint, defaultSort = 'created_at', defaultDir = 'desc', defaultStatus = null) {
  return {
    items: [],
    total: 0,
    limit: 25,
    offset: 0,
    sortBy: defaultSort,
    sortDir: defaultDir,
    search: '',
    status: defaultStatus,
    loading: true,
    error: null,
    drawer: null,
    refreshTimer: null,

    get totalPages() { return Math.max(1, Math.ceil(this.total / this.limit)); },
    get currentPage() { return Math.floor(this.offset / this.limit) + 1; },
    get hasPrev() { return this.offset > 0; },
    get hasNext() { return this.offset + this.limit < this.total; },
    get pageStart() { return this.total === 0 ? 0 : this.offset + 1; },
    get pageEnd() { return Math.min(this.offset + this.limit, this.total); },

    buildUrl() {
      const p = new URLSearchParams({
        limit: this.limit,
        offset: this.offset,
        sort_by: this.sortBy,
        sort_dir: this.sortDir,
      });
      if (this.search) p.set('search', this.search);
      if (this.status) p.set('status', this.status);
      return `${endpoint}?${p}`;
    },

    async load() {
      this.loading = true;
      this.error = null;
      try {
        const res = await fetch(this.buildUrl());
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        this.items = data.items || [];
        this.total = data.total || 0;
      } catch (e) {
        this.error = e.message || 'Failed to load data';
      }
      this.loading = false;
    },

    sort(col) {
      if (this.sortBy === col) {
        this.sortDir = this.sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        this.sortBy = col;
        this.sortDir = 'asc';
      }
      this.offset = 0;
      this.load();
    },

    sortIcon(col) {
      if (this.sortBy !== col) return '↕';
      return this.sortDir === 'asc' ? '↑' : '↓';
    },

    prevPage() {
      if (this.hasPrev) { this.offset = Math.max(0, this.offset - this.limit); this.load(); }
    },

    nextPage() {
      if (this.hasNext) { this.offset += this.limit; this.load(); }
    },

    setPageSize(n) {
      this.limit = parseInt(n);
      this.offset = 0;
      this.load();
    },

    onSearch: debounce(function() { this.offset = 0; this.load(); }, 350),

    openDrawer(item) { this.drawer = item; },
    closeDrawer() { this.drawer = null; },

    init() {
      this.load();
      this.refreshTimer = setInterval(() => this.load(), 30000);
    },

    destroy() {
      if (this.refreshTimer) clearInterval(this.refreshTimer);
      this.drawer = null;
    },
  };
}

// ─── Page: Clients ────────────────────────────────────────────────────────────

function clientsPage() {
  return {
    ...makeGrid('/admin/api/clients', 'created_at', 'desc'),

    async deleteClient(item, event) {
      event.stopPropagation();
      if (!confirm(`Delete client "${item.name}"? This cannot be undone.`)) return;
      const res = await fetch(`/admin/api/clients/${item.id}`, { method: 'DELETE' });
      if (res.ok) this.load();
      else alert('Failed to delete client');
    },
  };
}

// ─── Page: Tokens ─────────────────────────────────────────────────────────────

function tokensPage() {
  return {
    ...makeGrid('/admin/api/tokens', 'expires_at', 'desc', 'active'),

    tokenStatus(t) {
      if (t.revoked) return { label: 'Revoked', cls: 'badge-red' };
      if (t.expired) return { label: 'Expired', cls: 'badge-yellow' };
      return { label: 'Active', cls: 'badge-green' };
    },

    async revokeToken(item, event) {
      event.stopPropagation();
      if (!confirm('Revoke this token?')) return;
      const res = await fetch(`/admin/api/tokens/${item.id}/revoke`, { method: 'POST' });
      if (res.ok) this.load();
      else alert('Failed to revoke token');
    },
  };
}

// ─── Page: Users ──────────────────────────────────────────────────────────────

function usersPage() {
  return {
    ...makeGrid('/admin/api/users', 'created_at', 'desc'),
  };
}

// ─── Page: Device Authorizations ─────────────────────────────────────────────

function devicePage() {
  return {
    ...makeGrid('/admin/api/device', 'expires_at', 'desc', 'pending'),

    deviceStatus(d) {
      if (d.approved) return { label: 'Approved', cls: 'badge-green' };
      if (d.denied)   return { label: 'Denied',   cls: 'badge-red' };
      if (d.expired)  return { label: 'Expired',  cls: 'badge-yellow' };
      if (d.used)     return { label: 'Used',     cls: 'badge-gray' };
      return { label: 'Pending', cls: 'badge-blue' };
    },

    async expireCode(item, event) {
      event.stopPropagation();
      if (!confirm('Force-expire this device code?')) return;
      const res = await fetch(`/admin/api/device/${item.device_code}/expire`, { method: 'POST' });
      if (res.ok) this.load();
      else alert('Failed to expire device code');
    },
  };
}

// ─── Page: JWT Keys ───────────────────────────────────────────────────────────

function keysPage() {
  return {
    keys: [],
    loading: true,
    rotating: false,
    rotateAlgorithm: 'RS256',
    rotateGrace: 24,
    error: null,

    async init() {
      await this.load();
    },

    async load() {
      this.loading = true;
      this.error = null;
      try {
        const res = await fetch('/admin/api/keys');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        this.keys = data.keys || [];
      } catch (e) {
        this.error = e.message;
      }
      this.loading = false;
    },

    async rotate() {
      this.rotating = true;
      try {
        const res = await fetch('/admin/api/keys/rotate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            algorithm: this.rotateAlgorithm,
            grace_period_hours: parseInt(this.rotateGrace),
          }),
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Rotation failed');
        Alpine.store('router').showRotateModal = false;
        await this.load();
      } catch (e) {
        alert(e.message);
      }
      this.rotating = false;
    },

    keyAge(created) {
      if (!created) return null;
      return Math.floor((Date.now() - new Date(created).getTime()) / 86400000);
    },
  };
}

// ─── Rotate modal (body-level, outside any x-show parent) ─────────────────────
function rotateModalData() {
  return {
    rotating: false,
    rotateAlgorithm: 'RS256',
    rotateGrace: 24,

    async rotate() {
      this.rotating = true;
      try {
        const res = await fetch('/admin/api/keys/rotate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            algorithm: this.rotateAlgorithm,
            grace_period_hours: parseInt(this.rotateGrace),
          }),
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Rotation failed');
        Alpine.store('router').showRotateModal = false;
      } catch (e) {
        alert(e.message);
      }
      this.rotating = false;
    },
  };
}

// ─── Page: Metrics ────────────────────────────────────────────────────────────

function metricsPage() {
  return {
    loading: true,
    metrics: {},
    refreshInterval: null,

    async init() {
      await this.load();
      this.refreshInterval = setInterval(() => this.load(), 15000);
    },

    destroy() {
      if (this.refreshInterval) clearInterval(this.refreshInterval);
    },

    async load() {
      this.loading = !this.metrics || Object.keys(this.metrics).length === 0;
      _prometheusCache.ts = 0;
      this.metrics = await fetchPrometheus();
      this.loading = false;
      this.$nextTick(() => this.drawCharts());
    },

    scalar(name) { return prometheusScalar(this.metrics, name); },
    labeled(name, label, value) { return prometheusLabeled(this.metrics, name, label, value); },

    hq(name, q) { return histogramQuantile(this.metrics, name, q); },

    drawCharts() {
      const opts = baseChartOpts();

      createOrUpdateChart('m-tokens', {
        type: 'bar',
        data: {
          labels: ['Issued', 'Revoked', 'Auth Codes', 'Failed Auth'],
          datasets: [{
            data: [
              this.scalar('oauth2_server_oauth_token_issued_total'),
              this.scalar('oauth2_server_oauth_token_revoked_total'),
              this.scalar('oauth2_server_oauth_authorization_codes_issued'),
              this.scalar('oauth2_server_oauth_failed_authentications'),
            ],
            backgroundColor: [PALETTE.indigo, PALETTE.rose, PALETTE.emerald, PALETTE.amber],
            borderRadius: 6, borderSkipped: false, barThickness: 32,
          }],
        },
        options: opts,
      });

      // HTTP latency — computed from buckets
      const hp50 = this.hq('oauth2_server_http_request_duration_seconds', 0.5)  * 1000;
      const hp95 = this.hq('oauth2_server_http_request_duration_seconds', 0.95) * 1000;
      const hp99 = this.hq('oauth2_server_http_request_duration_seconds', 0.99) * 1000;
      createOrUpdateChart('m-latency', {
        type: 'bar',
        data: {
          labels: ['p50', 'p95', 'p99'],
          datasets: [{
            label: 'ms',
            data: [hp50.toFixed(1), hp95.toFixed(1), hp99.toFixed(1)],
            backgroundColor: [PALETTE.cyan, PALETTE.indigo, PALETTE.violet],
            borderRadius: 6, borderSkipped: false, barThickness: 32,
          }],
        },
        options: { ...opts, indexAxis: 'y' },
      });

      // DB query latency — computed from buckets
      const dp50 = this.hq('oauth2_server_db_query_duration_seconds', 0.5)  * 1000;
      const dp95 = this.hq('oauth2_server_db_query_duration_seconds', 0.95) * 1000;
      const dp99 = this.hq('oauth2_server_db_query_duration_seconds', 0.99) * 1000;
      createOrUpdateChart('m-db', {
        type: 'bar',
        data: {
          labels: ['p50', 'p95', 'p99'],
          datasets: [{
            label: 'ms',
            data: [dp50.toFixed(1), dp95.toFixed(1), dp99.toFixed(1)],
            backgroundColor: [PALETTE.cyan, PALETTE.emerald, PALETTE.amber],
            borderRadius: 6, borderSkipped: false, barThickness: 32,
          }],
        },
        options: { ...opts, indexAxis: 'y' },
      });

      createOrUpdateChart('m-resilience', {
        type: 'bar',
        data: {
          labels: ['Rate-limit', 'CB trips', 'Back-pressure', 'In-flight'],
          datasets: [{
            data: [
              this.scalar('oauth2_server_rate_limit_rejected_total'),
              this.scalar('oauth2_server_circuit_breaker_trips_total'),
              this.scalar('oauth2_server_back_pressure_rejected_total'),
              this.scalar('oauth2_server_concurrent_requests_in_flight'),
            ],
            backgroundColor: [PALETTE.amber, PALETTE.rose, PALETTE.violet, PALETTE.indigo],
            borderRadius: 6, borderSkipped: false, barThickness: 32,
          }],
        },
        options: opts,
      });
    },
  };
}

// ─── Page: Events ─────────────────────────────────────────────────────────────

function eventsPage() {
  return {
    ...makeGrid('/admin/api/events/recent', 'created_at', 'desc'),
    pluginHealth: null,

    async init() {
      this.load();
      this.loadHealth();
    },

    async loadHealth() {
      try {
        const res = await fetch('/events/health');
        if (res.ok) this.pluginHealth = await res.json();
      } catch (_) {}
    },
  };
}

// ─── Theme init (run before Alpine) ──────────────────────────────────────────

(function initThemeEarly() {
  const saved = localStorage.getItem('oauth2-admin-theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  if (saved === 'dark' || (!saved && prefersDark)) {
    document.documentElement.classList.add('dark');
  }
})();
