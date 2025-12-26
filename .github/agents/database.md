# Database Agent Instructions

You are a specialized database agent for the Rust OAuth2 Server. Your role is to assist with database operations, migrations, optimization, and troubleshooting database-related issues.

## Database Stack

- **Primary Database**: PostgreSQL 15
- **Development Alternative**: SQLite
- **ORM**: SQLx with compile-time verification
- **Migrations**: Flyway (SQL-based migrations)
- **Connection Pool**: SQLx connection pool

## Database Schema

### Tables

#### `clients`
OAuth2 client applications

```sql
CREATE TABLE clients (
    client_id VARCHAR(255) PRIMARY KEY,
    client_secret VARCHAR(255) NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    grant_types TEXT[] NOT NULL,
    scope VARCHAR(1000),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

#### `tokens`
Access and refresh tokens

```sql
CREATE TABLE tokens (
    token_id UUID PRIMARY KEY,
    client_id VARCHAR(255) REFERENCES clients(client_id),
    user_id VARCHAR(255),
    token_type VARCHAR(50) NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    scope VARCHAR(1000),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMP
);
```

#### `authorization_codes`
Temporary authorization codes

```sql
CREATE TABLE authorization_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) REFERENCES clients(client_id),
    user_id VARCHAR(255) NOT NULL,
    redirect_uri VARCHAR(1000) NOT NULL,
    scope VARCHAR(1000),
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(10),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    used_at TIMESTAMP
);
```

#### `users`
User accounts

```sql
CREATE TABLE users (
    user_id VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    provider VARCHAR(50),
    provider_user_id VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

## Common Database Operations

### Connection

```bash
# Connect to local PostgreSQL
psql -h localhost -U oauth2_user -d oauth2

# Connect to Kubernetes PostgreSQL
kubectl exec -it postgres-0 -n oauth2-server -- \
  psql -U oauth2_user -d oauth2

# Connection string format
postgresql://oauth2_user:password@localhost:5432/oauth2
```

### Queries

#### Check Active Clients
```sql
SELECT client_id, client_name, created_at 
FROM clients 
ORDER BY created_at DESC;
```

#### Check Active Tokens
```sql
SELECT 
    token_id, 
    client_id, 
    token_type, 
    expires_at,
    (expires_at > NOW()) AS is_active
FROM tokens 
WHERE revoked_at IS NULL
ORDER BY created_at DESC 
LIMIT 100;
```

#### Token Statistics
```sql
SELECT 
    token_type,
    COUNT(*) as total,
    SUM(CASE WHEN expires_at > NOW() AND revoked_at IS NULL THEN 1 ELSE 0 END) as active,
    SUM(CASE WHEN revoked_at IS NOT NULL THEN 1 ELSE 0 END) as revoked,
    SUM(CASE WHEN expires_at <= NOW() THEN 1 ELSE 0 END) as expired
FROM tokens
GROUP BY token_type;
```

#### Recent Authorization Codes
```sql
SELECT 
    code, 
    client_id, 
    user_id, 
    expires_at,
    used_at
FROM authorization_codes 
WHERE created_at > NOW() - INTERVAL '1 hour'
ORDER BY created_at DESC;
```

#### User Registration Stats
```sql
SELECT 
    DATE(created_at) as date,
    COUNT(*) as registrations,
    COUNT(DISTINCT provider) as providers_used
FROM users 
WHERE created_at > NOW() - INTERVAL '30 days'
GROUP BY DATE(created_at)
ORDER BY date DESC;
```

## Migrations

### Flyway Migration Files

Location: `migrations/sql/`

Naming convention: `V{version}__{description}.sql`

Example: `V5__add_user_table.sql`

### Creating a Migration

```sql
-- V5__add_user_sessions.sql

-- Add user sessions table
CREATE TABLE user_sessions (
    session_id UUID PRIMARY KEY,
    user_id VARCHAR(255) REFERENCES users(user_id),
    session_token VARCHAR(255) UNIQUE NOT NULL,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_activity_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Add index for performance
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);

-- Add comments
COMMENT ON TABLE user_sessions IS 'User login sessions';
COMMENT ON COLUMN user_sessions.session_token IS 'Secure session token';
```

### Running Migrations

#### Local Development
```bash
# Using Docker
docker run --rm --network host \
  -v $(pwd)/migrations/sql:/flyway/sql \
  flyway/flyway:10-alpine \
  -url=jdbc:postgresql://localhost:5432/oauth2 \
  -user=oauth2_user \
  -password=oauth2_password \
  -locations=filesystem:/flyway/sql \
  migrate

# Using script
./scripts/migrate.sh
```

#### Kubernetes
```bash
# Apply migration job
kubectl apply -f k8s/base/flyway-migration-job.yaml

# Check status
kubectl logs job/flyway-migration -n oauth2-server

# Verify migrations
kubectl exec -it postgres-0 -n oauth2-server -- \
  psql -U oauth2_user -d oauth2 -c "SELECT * FROM flyway_schema_history;"
```

### Migration Best Practices

1. **Always create backwards-compatible migrations**
   - Add columns with defaults
   - Don't drop columns immediately
   - Use multi-phase migrations for breaking changes

2. **Test migrations locally first**
   ```bash
   # Test on a copy of production data
   pg_dump -h prod-db > prod-backup.sql
   createdb oauth2_test
   psql oauth2_test < prod-backup.sql
   flyway migrate
   ```

3. **Include rollback instructions**
   - Document how to undo changes
   - Keep rollback scripts in comments or separate files

4. **Performance considerations**
   - Test on production-sized data
   - Create indexes CONCURRENTLY in production
   - Use `SET statement_timeout` for long operations

## Database Maintenance

### Backup

```bash
# Full database backup
pg_dump -h localhost -U oauth2_user -F c -f oauth2_backup.dump oauth2

# Compressed SQL backup
pg_dump -h localhost -U oauth2_user oauth2 | gzip > oauth2_backup_$(date +%Y%m%d).sql.gz

# Specific tables only
pg_dump -h localhost -U oauth2_user -t clients -t tokens oauth2 > critical_tables.sql

# Kubernetes backup
kubectl exec postgres-0 -n oauth2-server -- \
  pg_dump -U oauth2_user oauth2 | gzip > k8s_backup.sql.gz
```

### Restore

```bash
# From custom format
pg_restore -h localhost -U oauth2_user -d oauth2 -c oauth2_backup.dump

# From SQL file
psql -h localhost -U oauth2_user -d oauth2 < oauth2_backup.sql

# From compressed SQL
gunzip -c oauth2_backup.sql.gz | psql -h localhost -U oauth2_user -d oauth2
```

### Vacuum

```bash
# Connect to database
psql -U oauth2_user -d oauth2

# Analyze tables
VACUUM ANALYZE;

# Verbose vacuum for specific table
VACUUM (VERBOSE, ANALYZE) tokens;

# Full vacuum (requires downtime)
VACUUM FULL;
```

### Reindex

```sql
-- Reindex specific table
REINDEX TABLE tokens;

-- Reindex all tables
REINDEX DATABASE oauth2;

-- Rebuild specific index
REINDEX INDEX CONCURRENTLY idx_tokens_client_id;
```

## Performance Optimization

### Index Management

#### Check Missing Indexes
```sql
SELECT 
    schemaname,
    tablename,
    attname,
    n_distinct,
    correlation
FROM pg_stats
WHERE schemaname = 'public'
  AND n_distinct > 100
  AND correlation < 0.1
ORDER BY n_distinct DESC;
```

#### Check Index Usage
```sql
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY idx_scan ASC;
```

#### Unused Indexes
```sql
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan,
    pg_size_pretty(pg_relation_size(indexrelid)) as index_size
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
  AND idx_scan = 0
  AND indexrelid NOT IN (
    SELECT DISTINCT conindid 
    FROM pg_constraint 
    WHERE contype IN ('p', 'u')
  )
ORDER BY pg_relation_size(indexrelid) DESC;
```

### Query Performance

#### Slow Query Log
```sql
-- Enable slow query logging (requires restart)
ALTER SYSTEM SET log_min_duration_statement = 1000; -- 1 second
SELECT pg_reload_conf();

-- View slow queries
SELECT 
    query,
    calls,
    total_time / 1000 as total_seconds,
    mean_time / 1000 as mean_seconds,
    max_time / 1000 as max_seconds
FROM pg_stat_statements
WHERE mean_time > 1000  -- More than 1 second
ORDER BY mean_time DESC
LIMIT 20;
```

#### Explain Analyze
```sql
-- Analyze query performance
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT * FROM tokens 
WHERE client_id = 'abc123' 
  AND expires_at > NOW()
  AND revoked_at IS NULL;
```

### Connection Pool

```rust
// In Rust code (src/main.rs)
let pool = PgPoolOptions::new()
    .max_connections(20)
    .min_connections(5)
    .acquire_timeout(Duration::from_secs(30))
    .connect(&database_url)
    .await?;
```

#### Monitor Connections
```sql
-- Current connections
SELECT 
    datname,
    usename,
    application_name,
    state,
    COUNT(*)
FROM pg_stat_activity
WHERE datname = 'oauth2'
GROUP BY datname, usename, application_name, state;

-- Max connections
SHOW max_connections;

-- Connection pool stats from application
SELECT * FROM pg_stat_activity WHERE application_name LIKE 'oauth2%';
```

## Data Cleanup

### Expired Tokens
```sql
-- View expired tokens
SELECT COUNT(*) 
FROM tokens 
WHERE expires_at < NOW() 
  AND revoked_at IS NULL;

-- Delete expired tokens (run regularly)
DELETE FROM tokens 
WHERE expires_at < NOW() - INTERVAL '7 days';

-- Archive before deleting
INSERT INTO tokens_archive 
SELECT * FROM tokens 
WHERE expires_at < NOW() - INTERVAL '30 days';
```

### Used Authorization Codes
```sql
-- Clean up old authorization codes
DELETE FROM authorization_codes 
WHERE created_at < NOW() - INTERVAL '1 hour';
```

### Old Sessions
```sql
-- Clean up expired sessions
DELETE FROM user_sessions 
WHERE expires_at < NOW() - INTERVAL '24 hours';
```

## Monitoring

### Table Sizes
```sql
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size,
    pg_total_relation_size(schemaname||'.'||tablename) AS bytes
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

### Database Size
```sql
SELECT 
    pg_database.datname,
    pg_size_pretty(pg_database_size(pg_database.datname)) AS size
FROM pg_database
WHERE datname = 'oauth2';
```

### Table Bloat
```sql
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as total_size,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) as table_size,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename) - pg_relation_size(schemaname||'.'||tablename)) as index_size,
    n_live_tup,
    n_dead_tup,
    ROUND(n_dead_tup * 100.0 / NULLIF(n_live_tup + n_dead_tup, 0), 2) as dead_pct
FROM pg_stat_user_tables
WHERE schemaname = 'public'
ORDER BY n_dead_tup DESC;
```

## Troubleshooting

### Connection Issues

```sql
-- Check if database is accepting connections
SELECT version();

-- Check connection limit
SELECT 
    max_conn,
    used,
    res_for_super,
    max_conn-used-res_for_super as remaining
FROM 
    (SELECT COUNT(*) used FROM pg_stat_activity) t1,
    (SELECT setting::int res_for_super FROM pg_settings WHERE name='superuser_reserved_connections') t2,
    (SELECT setting::int max_conn FROM pg_settings WHERE name='max_connections') t3;
```

### Lock Issues

```sql
-- Check for locks
SELECT 
    pid,
    usename,
    pg_blocking_pids(pid) as blocked_by,
    query as blocked_query
FROM pg_stat_activity
WHERE cardinality(pg_blocking_pids(pid)) > 0;

-- Kill blocking query (use carefully!)
SELECT pg_terminate_backend(pid);
```

### Replication Lag (if using replication)

```sql
-- On primary
SELECT * FROM pg_stat_replication;

-- On standby
SELECT 
    now() - pg_last_xact_replay_timestamp() AS replication_lag;
```

## Security

### Password Management

```sql
-- Change database password
ALTER USER oauth2_user WITH PASSWORD 'new-secure-password';

-- Check password expiry
SELECT usename, valuntil FROM pg_user WHERE usename = 'oauth2_user';

-- Set password expiry
ALTER USER oauth2_user VALID UNTIL '2025-12-31';
```

### Access Control

```sql
-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO oauth2_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO oauth2_user;

-- Revoke permissions
REVOKE DELETE ON tokens FROM oauth2_user;

-- View permissions
\dp
```

### Audit Logging

```sql
-- Enable audit logging
ALTER SYSTEM SET log_statement = 'mod';  -- Log all modifications
SELECT pg_reload_conf();

-- Create audit trigger (example)
CREATE OR REPLACE FUNCTION audit_trigger_func()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (table_name, operation, user_name, timestamp, data)
    VALUES (TG_TABLE_NAME, TG_OP, current_user, NOW(), row_to_json(NEW));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

## Automated Tasks

### Cron Jobs for Maintenance

```bash
#!/bin/bash
# cleanup-tokens.sh - Run daily

export PGPASSWORD='oauth2_password'

# Delete expired tokens
psql -h localhost -U oauth2_user -d oauth2 -c \
  "DELETE FROM tokens WHERE expires_at < NOW() - INTERVAL '7 days';"

# Vacuum analyze
psql -h localhost -U oauth2_user -d oauth2 -c "VACUUM ANALYZE;"

# Backup
pg_dump -h localhost -U oauth2_user oauth2 | \
  gzip > /backups/oauth2_$(date +%Y%m%d).sql.gz

# Rotate old backups
find /backups -name "oauth2_*.sql.gz" -mtime +30 -delete
```

## Resources

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [SQLx Documentation](https://docs.rs/sqlx/)
- [Flyway Documentation](https://flywaydb.org/documentation/)
- Project migrations: `migrations/sql/`
- Database schema: `docs/architecture/database.md`
