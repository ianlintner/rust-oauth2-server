# OpenTelemetry upgrade deferral

This change retains the supported OpenTelemetry 0.32 family. It does not
implement the upgrades proposed in #408, #410, or #412.

## Compatibility constraint

The resolved lockfile contains:

| crate | version |
|---|---|
| opentelemetry | 0.32.0 |
| opentelemetry_sdk | 0.32.1 |
| opentelemetry-otlp | 0.32.0 |
| opentelemetry-proto | 0.32.0 |
| tracing-opentelemetry | 0.33.0 |

The published manifest of `reqwest-tracing 0.7.1` exposes
`opentelemetry_0_32`, but no `opentelemetry_0_33` feature. Its 0.32 feature
uses `tracing-opentelemetry 0.33`, which binds OpenTelemetry 0.32.
`tracing-opentelemetry 0.34` instead binds OpenTelemetry 0.33.

`oauth2-social-login` installs `reqwest_tracing::TracingMiddleware` in its
provider HTTP client. An application tracer and middleware using different
OpenTelemetry instances cannot share the span extension holding the context.
The middleware can therefore omit `traceparent` even when compilation succeeds.

## Regression evidence and test scope

A throwaway bumped member test compiled with OpenTelemetry 0.33 and
`tracing-opentelemetry 0.34`, then failed because the real middleware did not
inject `traceparent`. A separate mixed-version workspace build failed with
incompatible `TracerProvider` trait implementations. The latter compile failure
is not evidence that a root runtime coherence test executed.

The replacement adds three lockfile/feature-selection checks and two middleware
propagation tests (root and social-login member). The middleware tests construct
the same middleware type used by production, install a real tracing layer and
propagator, and observe a nonzero header after the middleware runs. A test-only
terminal middleware returns an explicit response fixture before HTTP transport.
No server response is claimed, and no socket or proxy is contacted.

These tests cover dependency pairing and header injection, not delivery on the
wire, a remote provider, or the private production client-builder function.
Member test execution is explicitly added to CI because root-only commands do
not automatically exercise every member of this non-virtual workspace.

No resolved crate version, cargo-vet audit, or exemption is added; lockfile
changes are development-dependency edges only. Local full-suite SQLite failures
were also present on the unchanged base. Published final-head CI remains the
readiness gate; focused local checks alone are not an all-green CI claim.

## Reopen conditions

Reconsider the upgrade when all of the following are verified:

1. A chosen `reqwest-tracing` release supports the target OpenTelemetry line.
2. Application, middleware, SDK, OTLP, proto, and tracing bridge dependencies are
   updated coherently, with the member's matching middleware feature selected.
3. The graph checks are deliberately updated for that supported pairing and
   pass without duplicate OpenTelemetry-family versions.
4. Both real middleware header-injection tests pass on the upgraded family.
5. Existing supply-chain guards and final-head CI pass, followed by review.

Deferring an unsupported upgrade is not completing that upgrade, and this
replacement is not merge authorization.
