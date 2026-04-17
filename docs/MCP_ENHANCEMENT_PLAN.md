# MCP Server Enhancement Plan

This document outlines proposed enhancements to the OAuth2 MCP server to support AI-assisted development workflows beyond OAuth2 operations.

## Current State (10 tools)

The MCP server currently provides:
1. `register_client` - Register OAuth2 client
2. `get_token` - Get access token (client_credentials)
3. `exchange_code` - Exchange authorization code
4. `refresh_token` - Refresh token
5. `introspect_token` - Introspect token
6. `revoke_token` - Revoke token
7. `get_health` - Server health
8. `get_readiness` - Server readiness
9. `get_metrics` - Prometheus metrics
10. `get_openid_config` - OIDC discovery

## Proposed Enhancements

### Category 1: Read-Only Development Tools

**Purpose**: Help AI understand codebase structure and status

1. **`get_project_info`**
   - Returns: Project name, version, description
   - Source: Cargo.toml root workspace
   - Use case: Understanding project context

2. **`list_crates`**
   - Returns: List of workspace crates with descriptions
   - Source: Parse Cargo.toml files
   - Use case: Understanding project structure

3. **`get_dependencies`**
   - Input: Optional crate name
   - Returns: Dependencies for crate or entire workspace
   - Source: Cargo.toml
   - Use case: Understanding dependencies before suggesting changes

4. **`check_build_status`**
   - Returns: Last build status, warnings, errors
   - Source: Execute `cargo check --message-format=json`
   - Use case: Pre-change validation

### Category 2: Test Execution Tools

**Purpose**: Allow AI to run tests and interpret results

5. **`run_tests`**
   - Input: Optional test filter
   - Returns: Test results, pass/fail counts
   - Source: Execute `cargo test --message-format=json`
   - Use case: Validating changes

6. **`run_rfc_compliance_tests`**
   - Returns: RFC compliance test results
   - Source: Execute `cargo test --test rfc_compliance`
   - Use case: RFC compliance validation

7. **`run_security_tests`**
   - Returns: Security test results
   - Source: Execute `cargo test --test security_http`
   - Use case: Security validation

### Category 3: Code Quality Tools

**Purpose**: Check code quality and style

8. **`check_formatting`**
   - Returns: Formatting issues
   - Source: Execute `cargo fmt --all -- --check`
   - Use case: Pre-commit validation

9. **`run_clippy`**
   - Returns: Clippy warnings and errors
   - Source: Execute `cargo clippy --message-format=json`
   - Use case: Linting

### Category 4: Database Tools (Safe Read-Only)

**Purpose**: Inspect database schema without modifications

10. **`get_schema_info`**
    - Returns: Database schema summary
    - Source: Read migration files in migrations/sql/
    - Use case: Understanding database structure

11. **`list_migrations`**
    - Returns: List of applied and pending migrations
    - Source: List files in migrations/sql/
    - Use case: Migration status

### Category 5: Documentation Tools

**Purpose**: Access documentation

12. **`get_agent_instructions`**
    - Input: Agent name (development, operations, database, security)
    - Returns: Agent instruction content
    - Source: Read .github/agents/{agent}.md
    - Use case: Understanding domain-specific guidelines

13. **`search_documentation`**
    - Input: Search term
    - Returns: Relevant documentation sections
    - Source: Search docs/ directory
    - Use case: Finding relevant docs

## Implementation Considerations

### Security

- **No Write Operations**: All new tools are read-only
- **No Direct DB Access**: Database tools only read migration files
- **Command Injection Prevention**: Use child_process with array args, not shell strings
- **Output Size Limits**: Truncate large outputs (max 10KB per response)
- **Timeout Limits**: 30 second timeout for all operations

### Implementation Approach

```javascript
// Add to OAuth2Client class

async runTests(filter = '') {
  const { exec } = await import('child_process');
  const { promisify } = await import('util');
  const execPromise = promisify(exec);

  const args = ['test', '--message-format=json'];
  if (filter) args.push(filter);

  const { stdout, stderr } = await execPromise(
    `cargo ${args.join(' ')}`,
    { timeout: 60000, maxBuffer: 1024 * 1024 }
  );

  // Parse JSON output
  const results = stdout.split('\n')
    .filter(line => line.trim())
    .map(line => JSON.parse(line))
    .filter(msg => msg.type === 'test');

  return {
    passed: results.filter(r => r.event === 'ok').length,
    failed: results.filter(r => r.event === 'failed').length,
    results: results.slice(0, 20) // Limit output
  };
}

async getProjectInfo() {
  const { readFile } = await import('fs/promises');
  const toml = await import('toml');

  const cargoToml = await readFile('Cargo.toml', 'utf-8');
  const parsed = toml.parse(cargoToml);

  return {
    name: parsed.package?.name || parsed.workspace?.name,
    version: parsed.package?.version,
    description: parsed.package?.description,
    workspace: !!parsed.workspace,
    members: parsed.workspace?.members || []
  };
}

async getAgentInstructions(agentName) {
  const { readFile } = await import('fs/promises');
  const path = `.github/agents/${agentName}.md`;

  try {
    const content = await readFile(path, 'utf-8');
    return { agent: agentName, content };
  } catch (error) {
    throw new Error(`Agent not found: ${agentName}`);
  }
}
```

### Alternative: Separate MCP Server

Instead of adding to the existing OAuth2 MCP server, create a separate **Development MCP Server**:

**Advantages**:
- Clear separation of concerns
- OAuth2 MCP stays lightweight
- Can have different security models
- Easier to maintain

**Location**: `mcp-server-dev/`

**Structure**:
```
mcp-server-dev/
  src/
    index.js          # Development MCP server
  package.json
  .env.example
  README.md
```

**Configuration**:
```json
{
  "mcpServers": {
    "oauth2-server": {
      "command": "node",
      "args": ["mcp-server/src/index.js"],
      "env": { "OAUTH2_BASE_URL": "http://localhost:8080" }
    },
    "oauth2-dev": {
      "command": "node",
      "args": ["mcp-server-dev/src/index.js"],
      "env": { "PROJECT_ROOT": "/path/to/rust-oauth2-server" }
    }
  }
}
```

## Recommendation

**Create separate Development MCP Server** for these reasons:

1. **Security**: OAuth2 MCP is read-only HTTP client, Dev MCP executes commands
2. **Scope**: Different purposes (OAuth2 operations vs development workflow)
3. **Maintainability**: Easier to update independently
4. **Deployment**: OAuth2 MCP could be used in production, Dev MCP is local only

## Next Steps

1. Create `mcp-server-dev/` directory
2. Implement core development tools (project info, tests, linting)
3. Add documentation
4. Test with Claude Desktop
5. Document in AGENTIC_QUICKSTART.md
6. Update README.md "For AI Agents" section

## Priority Tooling

**Phase 1** (Immediate value):
- `run_tests` with filtering
- `check_formatting`
- `run_clippy`
- `get_project_info`

**Phase 2** (High value):
- `run_rfc_compliance_tests`
- `run_security_tests`
- `list_crates`
- `get_agent_instructions`

**Phase 3** (Nice to have):
- `get_dependencies`
- `check_build_status`
- `list_migrations`
- `search_documentation`

## Testing Plan

1. Create sample client configuration
2. Test each tool individually
3. Verify output parsing
4. Test error handling
5. Validate security (no command injection)
6. Test timeout handling
7. Integration with Claude Desktop

## Documentation Updates

Files to update:
- `mcp-server-dev/README.md` - New server documentation
- `AGENTIC_QUICKSTART.md` - Add development MCP server section
- `README.md` - Update "For AI Agents" section
- `docs/AI_TOOLING_ENHANCEMENTS.md` - Mark Phase 3 complete

## Notes

- Keep OAuth2 MCP server unchanged (stable API)
- Development MCP server is local-only (never expose to network)
- All command execution must be safe (no shell=true)
- Output must be truncated to prevent context overflow
- Timeouts prevent hanging operations
- This complements Skills - Skills provide workflows, MCP provides tools
