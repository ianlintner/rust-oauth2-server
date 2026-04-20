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
    gridColor: dark ? 'rgba(148,163,184,0.15)' : 'rgba(148,163,184,0.3)',
    textColor: dark ? '#94a3b8' : '#64748b',
    bg: dark ? '#1e293b' : '#ffffff',
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
      const { textColor, gridColor } = chartDefaults();

      const scaleOpts = {
        x: { ticks: { color: textColor }, grid: { color: gridColor } },
        y: { beginAtZero: true, ticks: { color: textColor }, grid: { color: gridColor } },
      };

      // Token issued/revoked bar chart from metrics counters
      const issued = prometheusScalar(m, 'oauth2_server_oauth_token_issued_total');
      const revoked = prometheusScalar(m, 'oauth2_server_oauth_token_revoked_total');
      createOrUpdateChart('tokenChart', {
        type: 'bar',
        data: {
          labels: ['Issued', 'Revoked'],
          datasets: [{ data: [issued, revoked], backgroundColor: ['#2563eb', '#ef4444'] }],
        },
        options: { responsive: true, plugins: { legend: { display: false } }, scales: scaleOpts },
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
          datasets: [{ data: [s2xx, s4xx, s5xx], backgroundColor: ['#10b981', '#f59e0b', '#ef4444'] }],
        },
        options: { responsive: true, plugins: { legend: { position: 'bottom' } } },
      });

      // Latency p50/p95/p99 — use fake buckets if histogram quantiles not available
      const p50 = prometheusLabeled(m, 'oauth2_server_http_request_duration_seconds', 'quantile', '0.5') * 1000;
      const p95 = prometheusLabeled(m, 'oauth2_server_http_request_duration_seconds', 'quantile', '0.95') * 1000;
      const p99 = prometheusLabeled(m, 'oauth2_server_http_request_duration_seconds', 'quantile', '0.99') * 1000;
      createOrUpdateChart('latencyChart', {
        type: 'bar',
        data: {
          labels: ['p50', 'p95', 'p99'],
          datasets: [{ label: 'ms', data: [p50, p95, p99], backgroundColor: '#8b5cf6' }],
        },
        options: {
          responsive: true,
          plugins: { legend: { display: false } },
          scales: {
            ...scaleOpts,
            y: { ...scaleOpts.y, title: { display: true, text: 'ms', color: textColor } },
          },
        },
      });

      // Rate-limit rejections
      const rl = prometheusScalar(m, 'oauth2_server_rate_limit_rejected_total');
      const cb = prometheusLabeled(m, 'oauth2_server_circuit_breaker_state', 'state', '1'); // 1=Open
      createOrUpdateChart('resilienceChart', {
        type: 'bar',
        data: {
          labels: ['Rate-limit rejects', 'Circuit trips'],
          datasets: [{ data: [rl, cb], backgroundColor: ['#f59e0b', '#ef4444'] }],
        },
        options: { responsive: true, plugins: { legend: { display: false } }, scales: scaleOpts },
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
    showRotateModal: false,
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
        this.showRotateModal = false;
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

    drawCharts() {
      const { textColor, gridColor } = chartDefaults();
      const scale = {
        x: { ticks: { color: textColor }, grid: { color: gridColor } },
        y: { beginAtZero: true, ticks: { color: textColor }, grid: { color: gridColor } },
      };

      // Auth metrics
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
            backgroundColor: ['#2563eb', '#ef4444', '#10b981', '#f59e0b'],
          }],
        },
        options: { responsive: true, plugins: { legend: { display: false } }, scales: scale },
      });

      // Latency
      createOrUpdateChart('m-latency', {
        type: 'bar',
        data: {
          labels: ['p50', 'p95', 'p99'],
          datasets: [{
            label: 'ms',
            data: [
              (this.labeled('oauth2_server_http_request_duration_seconds', 'quantile', '0.5') * 1000).toFixed(1),
              (this.labeled('oauth2_server_http_request_duration_seconds', 'quantile', '0.95') * 1000).toFixed(1),
              (this.labeled('oauth2_server_http_request_duration_seconds', 'quantile', '0.99') * 1000).toFixed(1),
            ],
            backgroundColor: '#8b5cf6',
          }],
        },
        options: { responsive: true, plugins: { legend: { display: false } }, scales: scale },
      });

      // DB query latency
      createOrUpdateChart('m-db', {
        type: 'bar',
        data: {
          labels: ['p50', 'p95', 'p99'],
          datasets: [{
            label: 'ms',
            data: [
              (this.labeled('oauth2_server_db_query_duration_seconds', 'quantile', '0.5') * 1000).toFixed(1),
              (this.labeled('oauth2_server_db_query_duration_seconds', 'quantile', '0.95') * 1000).toFixed(1),
              (this.labeled('oauth2_server_db_query_duration_seconds', 'quantile', '0.99') * 1000).toFixed(1),
            ],
            backgroundColor: '#06b6d4',
          }],
        },
        options: { responsive: true, plugins: { legend: { display: false } }, scales: scale },
      });

      // Resilience gauges
      createOrUpdateChart('m-resilience', {
        type: 'bar',
        data: {
          labels: ['Rate-limit rejects', 'CB trips', 'Backpressure rejects', 'In-flight'],
          datasets: [{
            data: [
              this.scalar('oauth2_server_rate_limit_rejected_total'),
              this.scalar('oauth2_server_circuit_breaker_trips_total'),
              this.scalar('oauth2_server_back_pressure_rejected_total'),
              this.scalar('oauth2_server_concurrent_requests_in_flight'),
            ],
            backgroundColor: ['#f59e0b', '#ef4444', '#f97316', '#6366f1'],
          }],
        },
        options: { responsive: true, plugins: { legend: { display: false } }, scales: scale },
      });
    },
  };
}

// ─── Page: Events ─────────────────────────────────────────────────────────────

function eventsPage() {
  return {
    ...makeGrid('/events/admin/recent', 'created_at', 'desc'),
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
