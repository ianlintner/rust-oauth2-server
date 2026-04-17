Run performance benchmarks.

## Available Benchmarks

The project includes a benchmark harness in `benchmarks/` directory.

**Run all benchmarks**:
```bash
cd benchmarks
cargo bench
```

**Specific benchmark suites**:
- Token generation performance
- Token validation performance
- Database query performance
- Authorization flow end-to-end
- Concurrent request handling

**Load testing**:
```bash
# Using Apache Bench
ab -n 1000 -c 10 http://localhost:8080/health

# Using wrk
wrk -t4 -c100 -d30s http://localhost:8080/health
```

**Profiling**:
```bash
# CPU profiling
cargo flamegraph --bin oauth2-server

# Memory profiling
valgrind --tool=massif target/release/oauth2-server
```

See `benchmarks/README.md` for detailed benchmark documentation.

Which benchmark would you like to run?
