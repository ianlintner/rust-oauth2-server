#!/usr/bin/env python3
"""Timing analyzer — detects timing side-channels via statistical comparison."""

import argparse
import json
import math
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone


def measure_endpoint(url: str, method: str, body: dict | None, n: int) -> list[float]:
    """Measure response time for n requests, return times in ms."""
    times = []
    data = None
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if body:
        data = urllib.parse.urlencode(body).encode()
    for _ in range(n):
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
        except Exception:
            pass
        elapsed = (time.perf_counter() - start) * 1000
        times.append(elapsed)
    return times


def welch_t_test(a: list[float], b: list[float]) -> tuple[float, float]:
    """Return (t_stat, p_value) for two-sample Welch's t-test."""
    n1, n2 = len(a), len(b)
    if n1 < 2 or n2 < 2:
        return 0.0, 1.0
    m1 = sum(a) / n1
    m2 = sum(b) / n2
    v1 = sum((x - m1) ** 2 for x in a) / (n1 - 1)
    v2 = sum((x - m2) ** 2 for x in b) / (n2 - 1)
    se = math.sqrt(v1 / n1 + v2 / n2) if (v1 / n1 + v2 / n2) > 0 else 1e-9
    t_stat = (m1 - m2) / se
    # Approximate p-value using normal distribution for large n
    p_value = 2 * (1 - _norm_cdf(abs(t_stat)))
    return t_stat, p_value


def _norm_cdf(x: float) -> float:
    """Approximate standard normal CDF."""
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


def main():
    parser = argparse.ArgumentParser(description="Timing side-channel analyzer")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    findings = []

    # Test: login timing for valid vs invalid username
    valid_user_times = measure_endpoint(
        f"{args.base_url}/auth/login", "POST",
        {"username": "admin", "password": "wrong_password_xyz"}, args.samples
    )
    invalid_user_times = measure_endpoint(
        f"{args.base_url}/auth/login", "POST",
        {"username": "definitely_nonexistent_user_12345", "password": "wrong_password_xyz"}, args.samples
    )

    avg_valid = sum(valid_user_times) / len(valid_user_times)
    avg_invalid = sum(invalid_user_times) / len(invalid_user_times)
    diff = abs(avg_valid - avg_invalid)
    t_stat, p_value = welch_t_test(valid_user_times, invalid_user_times)

    if p_value < 0.05 and diff > 3.0:
        findings.append({
            "id": "TIMING-001",
            "severity": "medium",
            "category": "runtime",
            "title": f"Login timing variance {diff:.1f}ms between valid/invalid usernames (p={p_value:.4f})",
            "evidence": {
                "endpoint": "/auth/login",
                "measurements": [
                    {"input": "valid_user", "avg_ms": round(avg_valid, 2), "samples": args.samples},
                    {"input": "invalid_user", "avg_ms": round(avg_invalid, 2), "samples": args.samples},
                ],
                "variance_ms": round(diff, 2),
                "t_statistic": round(t_stat, 4),
                "p_value": round(p_value, 6),
            },
            "reproducible": None,
            "follow_up_suggested": True,
        })

    # Test: token endpoint timing for valid vs invalid client
    valid_client_times = measure_endpoint(
        f"{args.base_url}/oauth/token", "POST",
        {"grant_type": "client_credentials", "client_id": "default_client",
         "client_secret": "wrong_secret", "scope": "read"}, args.samples
    )
    invalid_client_times = measure_endpoint(
        f"{args.base_url}/oauth/token", "POST",
        {"grant_type": "client_credentials", "client_id": "nonexistent_client_xyz",
         "client_secret": "wrong_secret", "scope": "read"}, args.samples
    )

    avg_vc = sum(valid_client_times) / len(valid_client_times)
    avg_ic = sum(invalid_client_times) / len(invalid_client_times)
    diff_c = abs(avg_vc - avg_ic)
    t_stat_c, p_value_c = welch_t_test(valid_client_times, invalid_client_times)

    if p_value_c < 0.05 and diff_c > 3.0:
        findings.append({
            "id": "TIMING-002",
            "severity": "medium",
            "category": "runtime",
            "title": f"Token endpoint timing variance {diff_c:.1f}ms between valid/invalid clients (p={p_value_c:.4f})",
            "evidence": {
                "endpoint": "/oauth/token",
                "measurements": [
                    {"input": "valid_client", "avg_ms": round(avg_vc, 2), "samples": args.samples},
                    {"input": "invalid_client", "avg_ms": round(avg_ic, 2), "samples": args.samples},
                ],
                "variance_ms": round(diff_c, 2),
                "t_statistic": round(t_stat_c, 4),
                "p_value": round(p_value_c, 6),
            },
            "reproducible": None,
            "follow_up_suggested": True,
        })

    result = {
        "scanner": "timing-analyzer",
        "config": args.config,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Timing analyzer: {len(findings)} findings for {args.config}")


if __name__ == "__main__":
    main()
