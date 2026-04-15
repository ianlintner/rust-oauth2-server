const { Provider } = require("oidc-provider");
const express = require("express");
const { Pool } = require("pg");

const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL ||
    "postgres://postgres:postgres@bench-postgres:5432/oauth2_node_oidc",
});

// Simple PostgreSQL adapter for oidc-provider
class PostgresAdapter {
  constructor(name) {
    this.name = name;
  }

  async upsert(id, payload, expiresIn) {
    const expiresAt = expiresIn
      ? new Date(Date.now() + expiresIn * 1000)
      : null;
    await pool.query(
      `INSERT INTO oidc_payloads (id, type, payload, expires_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (id, type) DO UPDATE SET payload = $3, expires_at = $4`,
      [id, this.name, JSON.stringify(payload), expiresAt],
    );
  }

  async find(id) {
    const result = await pool.query(
      "SELECT payload, expires_at FROM oidc_payloads WHERE id = $1 AND type = $2",
      [id, this.name],
    );
    if (!result.rows[0]) return undefined;
    const { payload, expires_at } = result.rows[0];
    if (expires_at && new Date(expires_at) < new Date()) return undefined;
    return JSON.parse(payload);
  }

  async findByUserCode(userCode) {
    const result = await pool.query(
      "SELECT payload FROM oidc_payloads WHERE type = $1 AND payload::jsonb->>'userCode' = $2",
      [this.name, userCode],
    );
    if (!result.rows[0]) return undefined;
    return JSON.parse(result.rows[0].payload);
  }

  async findByUid(uid) {
    const result = await pool.query(
      "SELECT payload FROM oidc_payloads WHERE type = $1 AND payload::jsonb->>'uid' = $2",
      [this.name, uid],
    );
    if (!result.rows[0]) return undefined;
    return JSON.parse(result.rows[0].payload);
  }

  async consume(id) {
    const now = Math.floor(Date.now() / 1000);
    await pool.query(
      `UPDATE oidc_payloads
       SET payload = jsonb_set(payload::jsonb, '{consumed}', to_jsonb($3::int))
       WHERE id = $1 AND type = $2`,
      [id, this.name, now],
    );
  }

  async destroy(id) {
    await pool.query("DELETE FROM oidc_payloads WHERE id = $1 AND type = $2", [
      id,
      this.name,
    ]);
  }

  async revokeByGrantId(grantId) {
    await pool.query(
      "DELETE FROM oidc_payloads WHERE type = $1 AND payload::jsonb->>'grantId' = $2",
      [this.name, grantId],
    );
  }
}

async function main() {
  // Initialize the database table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS oidc_payloads (
      id VARCHAR(255) NOT NULL,
      type VARCHAR(64) NOT NULL,
      payload TEXT NOT NULL,
      expires_at TIMESTAMPTZ,
      PRIMARY KEY (id, type)
    )
  `);

  const provider = new Provider("http://bench-node-oidc:3000", {
    adapter: PostgresAdapter,
    clients: [
      {
        client_id: "bench-client",
        client_secret: "bench-secret-12345678",
        grant_types: ["client_credentials"],
        response_types: [],
        scope: "openid profile email",
        token_endpoint_auth_method: "client_secret_post",
      },
    ],
    features: {
      clientCredentials: { enabled: true },
      introspection: { enabled: true },
      revocation: { enabled: true },
    },
    scopes: ["openid", "profile", "email"],
    ttl: {
      AccessToken: 3600,
      ClientCredentials: 3600,
    },
    // Disable unnecessary features for benchmark fairness
    cookies: { keys: ["benchmarksecretkey1234567890"] },
  });

  // This is a benchmark-only OIDC provider. CSRF protection is not required here since
  // it is an internal service with no user-facing forms that could be targeted cross-site.
  const app = express(); // nosemgrep: javascript.express.security.audit.express-check-csurf-middleware-usage

  // Health check endpoint
  app.get("/health", (req, res) => {
    res.json({ status: "ok" });
  });

  app.use(provider.callback());

  app.listen(3000, "0.0.0.0", () => {
    console.log("node-oidc-provider listening on port 3000");
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
