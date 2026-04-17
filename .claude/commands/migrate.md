Create a database migration following project conventions.

## Migration Details

Please provide:
1. **Description**: Brief description (e.g., "add_user_roles_table")
2. **Type**: Migration type
   - add_column: Add new column to existing table
   - add_table: Create new table
   - add_index: Create index for performance
   - modify_column: Change column definition
   - data_migration: Transform or clean data
3. **Target table**: Table being modified
4. **Backwards compatible**: true/false

## Process

The migration will:
1. Determine next version number (V13, V14, etc.)
2. Create migration file in `migrations/sql/`
3. Update storage backend code
4. Test migration locally
5. Run full test suite

Use the db-migration skill for detailed migration steps.

What migration would you like to create?
