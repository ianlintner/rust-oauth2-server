# Database Migration Skill

**Purpose**: Create and apply database schema migrations safely following project conventions.

**When to Use**:
- Adding new tables or columns
- Modifying existing schema
- Creating indexes for performance
- Data transformations or cleanup
- Schema version upgrades

## Parameters

- `migration_description`: Brief description of the migration (e.g., "add_token_endpoint_auth_method")
- `migration_type`: Type of change (add_column, add_table, add_index, modify_column, data_migration)
- `target_table`: Table being modified
- `backwards_compatible`: Whether migration can be rolled back (true/false)

## Prerequisites

- Understanding of current database schema
- Knowledge of SQL and Flyway migration conventions
- Local development environment with database access
- Backup of production data (if applying to production)

## Prompt

Create and apply a database migration with:
- Description: {{migration_description}}
- Type: {{migration_type}}
- Target table: {{target_table}}
- Backwards compatible: {{backwards_compatible}}

Please perform these steps:

1. **Schema Analysis Phase**:
   - Review current schema:
     ```bash
     # For SQLite
     sqlite3 /tmp/oauth2.db ".schema {{target_table}}"

     # For PostgreSQL
     psql $OAUTH2_DATABASE_URL -c "\d {{target_table}}"
     ```
   - Review existing migrations in `migrations/sql/`
   - Find the latest migration number:
     ```bash
     ls migrations/sql/ | grep "^V" | sort | tail -1
     ```
   - Check migration history:
     ```sql
     SELECT * FROM flyway_schema_history ORDER BY installed_rank DESC LIMIT 5;
     ```

2. **Design Migration**:
   - Determine next version number (e.g., V13 if latest is V12)
   - Plan SQL statements:
     - **Adding column**: ALTER TABLE ADD COLUMN with DEFAULT
     - **Adding table**: CREATE TABLE IF NOT EXISTS
     - **Adding index**: CREATE INDEX IF NOT EXISTS
     - **Data migration**: UPDATE/INSERT statements
   - Consider backwards compatibility:
     - Use DEFAULT values for new NOT NULL columns
     - Don't drop columns that may be in use
     - Test with existing data

3. **Create Migration File**:
   - Create file: `migrations/sql/V{version}__{description}.sql`
   - Naming format: `V13__add_token_endpoint_auth_method.sql`
   - Include header comment:
     ```sql
     -- Migration: V13 - Add token_endpoint_auth_method to clients table
     -- Date: 2026-04-17
     -- Purpose: Support public clients (RFC 9700, Phase 1.B)
     -- Backwards compatible: Yes
     ```

4. **Write Migration SQL**:

   **Example: Adding Column**
   ```sql
   -- Add token_endpoint_auth_method column with default value
   ALTER TABLE clients
   ADD COLUMN token_endpoint_auth_method VARCHAR(50)
   DEFAULT 'client_secret_basic' NOT NULL;

   -- Create index if needed
   CREATE INDEX IF NOT EXISTS idx_clients_auth_method
   ON clients(token_endpoint_auth_method);
   ```

   **Example: Adding Table**
   ```sql
   -- Create new table with proper constraints
   CREATE TABLE IF NOT EXISTS device_codes (
       device_code VARCHAR(255) PRIMARY KEY,
       user_code VARCHAR(20) NOT NULL UNIQUE,
       client_id VARCHAR(255) NOT NULL,
       scope VARCHAR(500),
       expires_at TIMESTAMP NOT NULL,
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       FOREIGN KEY (client_id) REFERENCES clients(client_id)
   );

   CREATE INDEX IF NOT EXISTS idx_device_codes_user_code
   ON device_codes(user_code);
   ```

   **Example: Data Migration**
   ```sql
   -- Safely update existing data
   UPDATE tokens
   SET token_type = 'Bearer'
   WHERE token_type IS NULL OR token_type = '';

   -- Add constraint after data is clean
   ALTER TABLE tokens
   ADD CONSTRAINT chk_token_type
   CHECK (token_type IN ('Bearer', 'DPoP'));
   ```

5. **Update Storage Backend**:
   - Update SQLx implementation in `crates/oauth2-storage-sqlx/src/sqlx.rs`:
     - Add field to struct
     - Update save_* methods with new columns
     - Update load_* methods to read new columns
     - Handle both SQLite and PostgreSQL syntax differences
   - Update MongoDB implementation in `crates/oauth2-storage-mongo/` if applicable
   - Update domain model in `crates/oauth2-core/src/models/` if needed

6. **Test Migration Locally**:
   ```bash
   # Backup current database
   cp /tmp/oauth2.db /tmp/oauth2.db.backup

   # Run migration
   flyway migrate -url=jdbc:sqlite:/tmp/oauth2.db -locations=filesystem:migrations/sql

   # Verify migration applied
   sqlite3 /tmp/oauth2.db ".schema {{target_table}}"

   # Run tests to verify compatibility
   cargo test --verbose --all-features --locked

   # Check specific functionality
   cargo test {{target_table}}_storage
   ```

7. **Rollback Testing** (if backwards_compatible=true):
   ```bash
   # Restore backup
   cp /tmp/oauth2.db.backup /tmp/oauth2.db

   # Verify old code still works
   cargo test
   ```

8. **Update Documentation**:
   - Add migration notes to CHANGELOG.md
   - Update schema documentation in `.github/agents/database.md`
   - Document new fields in CLAUDE.md if they affect invariants
   - Update API documentation if schema changes affect endpoints

## Success Criteria

- [ ] Migration file created with proper version number and naming
- [ ] SQL syntax is correct for both SQLite and PostgreSQL
- [ ] Backwards compatible (uses DEFAULT for new columns)
- [ ] Storage backend updated to handle new schema
- [ ] Migration applies successfully locally
- [ ] All tests pass after migration
- [ ] Schema matches expected state
- [ ] Rollback tested (if applicable)
- [ ] Documentation updated
- [ ] No data loss or corruption

## Common Issues & Solutions

### Issue: Migration fails with "column already exists"
**Solution**: Use `ADD COLUMN IF NOT EXISTS` or check column existence first
```sql
-- SQLite
ALTER TABLE clients ADD COLUMN new_column TEXT DEFAULT 'value';

-- PostgreSQL with conditional
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='clients' AND column_name='new_column') THEN
        ALTER TABLE clients ADD COLUMN new_column TEXT DEFAULT 'value';
    END IF;
END $$;
```

### Issue: Tests fail after migration
**Solution**:
- Update all 5 TokenActor::new() call sites if signature changed
- Update test fixtures in tests/rfc_compliance.rs and tests/security_http.rs
- Check app_data injection in test setup

### Issue: SQLite vs PostgreSQL syntax differences
**Solution**:
- SQLite: `AUTOINCREMENT`, `PRAGMA`
- PostgreSQL: `SERIAL`, `SEQUENCE`
- Use conditional logic in storage layer:
  ```rust
  if cfg!(feature = "sqlite") {
      // SQLite-specific query
  } else {
      // PostgreSQL query
  }
  ```

### Issue: Migration breaks existing deployments
**Solution**:
- Always use DEFAULT values for new NOT NULL columns
- Never drop columns that may be in use
- Use multi-phase migrations for breaking changes:
  - Phase 1: Add new column with default
  - Phase 2: Migrate data
  - Phase 3: Remove old column (separate release)

## Related Resources

- [Database Agent](../.github/agents/database.md) - Complete schema documentation
- [Flyway Documentation](https://flywaydb.org/documentation/)
- [SQLx Documentation](https://github.com/launchbadge/sqlx)
- [Migration Examples](../migrations/sql/)
- [Storage Implementation](../crates/oauth2-storage-sqlx/src/sqlx.rs)
- [CLAUDE.md - Common Pitfalls #3](../CLAUDE.md)

## Example Usage

### Add Column for Public Clients

```
Use the db-migration skill with:
- migration_description: add_token_endpoint_auth_method
- migration_type: add_column
- target_table: clients
- backwards_compatible: true
```

### Create Device Flow Table

```
Use the db-migration skill with:
- migration_description: create_device_codes_table
- migration_type: add_table
- target_table: device_codes
- backwards_compatible: true
```

### Add Performance Index

```
Use the db-migration skill with:
- migration_description: add_index_tokens_client_id
- migration_type: add_index
- target_table: tokens
- backwards_compatible: true
```

## Migration Checklist

- [ ] Latest migration number identified
- [ ] Migration file created with correct naming
- [ ] SQL tested in SQLite
- [ ] SQL tested in PostgreSQL
- [ ] Storage layer updated
- [ ] Tests updated for new schema
- [ ] Migration applied locally
- [ ] All tests pass
- [ ] Rollback tested
- [ ] Documentation updated
- [ ] CHANGELOG.md updated

## Production Deployment

For production migrations:

1. **Pre-deployment**:
   - Backup database: `pg_dump` or `sqlite3 .backup`
   - Test migration on staging environment
   - Verify rollback plan

2. **Deployment**:
   - Apply migration during maintenance window
   - Monitor application logs
   - Verify data integrity

3. **Post-deployment**:
   - Run smoke tests
   - Check metrics and alerts
   - Keep backup for 7+ days

## Notes

- Migration V12 added token_endpoint_auth_method (Phase 1.B)
- All migrations must work with both SQLite and PostgreSQL
- See CLAUDE.md §Common Pitfalls #3 for migration gotchas
- Always test migrations with existing data, not just fresh databases
- Coordinate with Database Agent for complex schema changes
