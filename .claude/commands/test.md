Run tests with optional filtering.

## Options

**All tests** (default):
```bash
cargo test --verbose --all-features --locked
```

**RFC compliance tests only**:
```bash
cargo test --test rfc_compliance
```

**Security tests only**:
```bash
cargo test --test security_http
```

**Device flow tests**:
```bash
cargo test --test device_flow
```

**Opaque token tests**:
```bash
cargo test --test opaque_tokens
```

**Specific test by name**:
```bash
cargo test test_name
```

**With debug output**:
```bash
RUST_LOG=debug cargo test test_name -- --nocapture
```

Which tests would you like to run?
