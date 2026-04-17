# Claude Code Skills for rust-oauth2-server

This directory contains reusable AI skills for common OAuth2 server development tasks. Skills are structured prompts that can be invoked by Claude Code and other AI assistants to perform complex, multi-step workflows.

## What are Skills?

Skills are parameterized, reusable AI workflows that:
- Encapsulate domain knowledge and best practices
- Provide step-by-step guidance for complex tasks
- Include validation and success criteria
- Link to relevant documentation and code examples

## Available Skills

### Development Skills

- **[oauth2-test-flow](oauth2-test-flow.md)** - Test OAuth2 authorization code + PKCE flow end-to-end
- **[oauth2-register-client](oauth2-register-client.md)** - Register and configure a new OAuth2 client
- **[oauth2-debug-token](oauth2-debug-token.md)** - Debug JWT token validation and claim issues
- **[add-endpoint](add-endpoint.md)** - Add a new HTTP endpoint with proper testing and documentation

### Compliance & Testing Skills

- **[rfc-compliance-check](rfc-compliance-check.md)** - Verify RFC compliance for OAuth2/OIDC features
- **[db-migration](db-migration.md)** - Create and apply database schema migrations

### Operations Skills

- **[deploy-k8s](deploy-k8s.md)** - Deploy the OAuth2 server to Kubernetes

## How to Use Skills

### With Claude Code

```bash
# Invoke a skill by name
claude skill oauth2-test-flow

# Or reference in conversation
"Use the oauth2-test-flow skill to verify the authorization code flow"
```

### Manual Usage

Each skill can also be used as a prompt template:
1. Open the skill markdown file
2. Copy the prompt section
3. Replace parameters with actual values
4. Use with any AI assistant

## Creating New Skills

To create a new skill:

1. Create a new markdown file in `.skills/` directory
2. Use this template structure:

```markdown
# Skill Name

**Purpose**: Brief description

**When to Use**: Specific scenarios

## Parameters

- `param1`: Description
- `param2`: Description

## Prompt

[Detailed prompt with {{param1}} and {{param2}} placeholders]

## Success Criteria

- [ ] Criterion 1
- [ ] Criterion 2

## Related Resources

- [Link to docs](../docs/...)
- [Link to agent instructions](../.github/agents/...)
```

3. Add the skill to this README
4. Test the skill with real parameters
5. Document any gotchas or common issues

## Skill Categories

### By Complexity

- **Simple** (5-10 min): oauth2-register-client, oauth2-debug-token
- **Medium** (15-30 min): oauth2-test-flow, add-endpoint, db-migration
- **Complex** (30+ min): rfc-compliance-check, deploy-k8s

### By Domain

- **Development**: add-endpoint, oauth2-debug-token
- **Testing**: oauth2-test-flow, rfc-compliance-check
- **Operations**: deploy-k8s
- **Database**: db-migration
- **Security**: oauth2-debug-token (token validation)

## Best Practices

1. **Be Specific**: Include exact commands and expected outputs
2. **Validate**: Always include success criteria and validation steps
3. **Link**: Reference relevant documentation and code
4. **Iterate**: Skills improve with usage - update based on learnings
5. **Test**: Verify skills work before committing

## Related Documentation

- [CLAUDE.md](../CLAUDE.md) - Agent memory and behavioral guidelines
- [AGENTIC_QUICKSTART.md](../AGENTIC_QUICKSTART.md) - Agent-focused quickstart
- [.github/agents/](../.github/agents/) - Specialized agent instructions
- [AI_TOOLING_ENHANCEMENTS.md](../docs/AI_TOOLING_ENHANCEMENTS.md) - Enhancement plan

## Feedback

Skills are living documents. If you find issues or have suggestions:
1. Create an issue describing the problem/improvement
2. Tag it with `ai-tooling` label
3. Reference the specific skill

## Version History

- **2026-04-17**: Initial skill library created with 7 core skills
