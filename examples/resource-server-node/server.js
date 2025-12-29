/*
  Minimal example "resource server" used by KIND E2E tests.

  It protects GET /protected by requiring a Bearer token and validating it via
  POST /oauth/introspect (RFC 7662).

  Environment variables:
    PORT (default: 8080)
    OAUTH2_INTROSPECT_URL (default: http://oauth2-server/oauth/introspect)
    OAUTH2_CLIENT_ID (required for introspection)
    OAUTH2_CLIENT_SECRET (required for introspection)
    REQUIRED_SCOPE (optional, e.g. "read")
*/

const http = require('http');
const { URL } = require('url');

const PORT = parseInt(process.env.PORT || '8080', 10);
const INTROSPECT_URL = process.env.OAUTH2_INTROSPECT_URL || 'http://oauth2-server/oauth/introspect';
const CLIENT_ID = process.env.OAUTH2_CLIENT_ID || '';
const CLIENT_SECRET = process.env.OAUTH2_CLIENT_SECRET || '';
const REQUIRED_SCOPE = (process.env.REQUIRED_SCOPE || '').trim();

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload)
  });
  res.end(payload);
}

function text(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(body);
}

function readBearerToken(req) {
  const h = req.headers['authorization'];
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1].trim() : null;
}

function scopeHas(required, scopeStr) {
  if (!required) return true;
  if (!scopeStr) return false;
  const parts = String(scopeStr).split(/\s+/).filter(Boolean);
  return parts.includes(required);
}

async function introspectToken(token) {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    return {
      ok: false,
      status: 500,
      error: 'resource_server_misconfigured',
      error_description: 'OAUTH2_CLIENT_ID/OAUTH2_CLIENT_SECRET not set'
    };
  }

  const params = new URLSearchParams({
    token,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET
  });

  const resp = await fetch(INTROSPECT_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString()
  });

  const textBody = await resp.text();
  let data;
  try {
    data = JSON.parse(textBody);
  } catch {
    return {
      ok: false,
      status: 502,
      error: 'bad_introspection_response',
      error_description: `Non-JSON response from introspection endpoint (status ${resp.status})`
    };
  }

  if (!resp.ok) {
    return {
      ok: false,
      status: 502,
      error: 'introspection_http_error',
      error_description: `Introspection endpoint returned ${resp.status}`,
      introspection: data
    };
  }

  return { ok: true, status: 200, introspection: data };
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

    if (req.method === 'GET' && url.pathname === '/health') {
      return text(res, 200, 'ok');
    }
    if (req.method === 'GET' && url.pathname === '/ready') {
      return text(res, 200, 'ok');
    }
    if (req.method === 'GET' && url.pathname === '/public') {
      return json(res, 200, { ok: true, public: true });
    }

    if (req.method === 'GET' && url.pathname === '/protected') {
      const token = readBearerToken(req);
      if (!token) {
        res.setHeader('WWW-Authenticate', 'Bearer');
        return json(res, 401, { ok: false, error: 'missing_token' });
      }

      const result = await introspectToken(token);
      if (!result.ok) {
        return json(res, result.status, {
          ok: false,
          error: result.error,
          error_description: result.error_description,
          ...(result.introspection ? { introspection: result.introspection } : {})
        });
      }

      const it = result.introspection || {};
      if (it.active !== true) {
        res.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
        return json(res, 401, { ok: false, error: 'invalid_token', introspection: it });
      }

      if (!scopeHas(REQUIRED_SCOPE, it.scope)) {
        res.setHeader('WWW-Authenticate', 'Bearer error="insufficient_scope"');
        return json(res, 403, {
          ok: false,
          error: 'insufficient_scope',
          required_scope: REQUIRED_SCOPE,
          scope: it.scope,
          introspection: it
        });
      }

      return json(res, 200, {
        ok: true,
        protected: true,
        required_scope: REQUIRED_SCOPE || null,
        introspection: it
      });
    }

    return json(res, 404, { ok: false, error: 'not_found' });
  } catch (e) {
    return json(res, 500, { ok: false, error: 'server_error', message: String(e && e.message ? e.message : e) });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  // Keep logs concise for CI
  console.log(`resource-server listening on 0.0.0.0:${PORT}`);
  console.log(`introspect url: ${INTROSPECT_URL}`);
  if (REQUIRED_SCOPE) console.log(`required scope: ${REQUIRED_SCOPE}`);
});
