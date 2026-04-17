Generate or update documentation.

## Documentation Types

**API documentation**:
```bash
# Generate Rust docs
cargo doc --open --all-features

# Build MkDocs site
python3 -m mkdocs build --strict
python3 -m mkdocs serve  # Preview at http://127.0.0.1:8000
```

**OpenAPI specification**:
The server exposes Swagger UI at `/swagger-ui` when running.
OpenAPI spec defined in `crates/oauth2-openapi/src/spec.rs`.

**Agent instructions**:
Located in `.github/agents/`:
- `development.md`: Development guidelines
- `operations.md`: Operations procedures
- `database.md`: Database operations
- `security.md`: Security practices

**Update locations**:
- `README.md`: Project overview
- `CLAUDE.md`: Agent memory and behavioral guidelines
- `AGENTIC_QUICKSTART.md`: Quick start for AI development
- `docs/`: User-facing documentation
- `.skills/`: AI skills library
- `.claude/commands/`: Slash commands

Which documentation would you like to generate or update?
