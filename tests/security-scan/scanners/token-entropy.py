#!/usr/bin/env python3
"""Token entropy validator — checks randomness of issued tokens."""

import argparse
import json
import math
import urllib.request
import urllib.parse
from collections import Counter
from datetime import datetime, timezone


def get_token(base_url: str, client_id: str, client_secret: str) -> str | None:
    """Request a client_credentials token, return access_token or None."""
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "read",
    }).encode()
    req = urllib.request.Request(
        f"{base_url}/oauth/token", data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            return body.get("access_token")
    except Exception:
        return None


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def register_client(base_url: str, cookie_jar_path: str) -> tuple[str, str] | None:
    """Register a test client using admin session cookie."""
    import http.cookiejar
    cj = http.cookiejar.MozillaCookieJar(cookie_jar_path)
    try:
        cj.load(ignore_discard=True, ignore_expires=True)
    except (FileNotFoundError, OSError, http.cookiejar.LoadError):
        return None
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    data = json.dumps({
        "client_name": "entropy-test",
        "redirect_uris": ["http://localhost:3000/callback"],
        "grant_types": ["client_credentials"],
        "scope": "read",
    }).encode()
    req = urllib.request.Request(
        f"{base_url}/admin/clients/register", data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with opener.open(req, timeout=10) as resp:
            body = json.loads(resp.read())
            return body.get("client_id"), body.get("client_secret")
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description="Token entropy validator")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--client-id", default="")
    parser.add_argument("--client-secret", default="")
    parser.add_argument("--cookie-jar", default="")
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    findings = []

    cid, csecret = args.client_id, args.client_secret
    if (not cid or not csecret) and args.cookie_jar:
        result = register_client(args.base_url, args.cookie_jar)
        if result:
            cid, csecret = result

    if not cid or not csecret:
        findings.append({
            "id": "ENTROPY-SKIP",
            "severity": "info",
            "category": "runtime",
            "title": "Could not obtain client credentials — skipping token entropy test",
            "evidence": {},
            "reproducible": None,
            "follow_up_suggested": False,
        })
    else:
        tokens = []
        for _ in range(args.count):
            t = get_token(args.base_url, cid, csecret)
            if t:
                tokens.append(t)

        if len(tokens) < 5:
            findings.append({
                "id": "ENTROPY-FAIL",
                "severity": "medium",
                "category": "runtime",
                "title": f"Only {len(tokens)}/{args.count} tokens obtained",
                "evidence": {"obtained": len(tokens), "requested": args.count},
                "reproducible": None,
                "follow_up_suggested": True,
            })
        else:
            # Check uniqueness
            unique = len(set(tokens))
            if unique < len(tokens):
                findings.append({
                    "id": "ENTROPY-DUP",
                    "severity": "critical",
                    "category": "runtime",
                    "title": f"Duplicate tokens detected: {len(tokens)-unique} duplicates in {len(tokens)} tokens",
                    "evidence": {"total": len(tokens), "unique": unique},
                    "reproducible": None,
                    "follow_up_suggested": True,
                })

            # Check entropy
            entropies = [shannon_entropy(t) for t in tokens]
            avg_entropy = sum(entropies) / len(entropies)
            min_entropy = min(entropies)

            # JWTs typically have high entropy (>4.0 bits/char)
            if min_entropy < 3.0:
                findings.append({
                    "id": "ENTROPY-LOW",
                    "severity": "high",
                    "category": "runtime",
                    "title": f"Low token entropy: min={min_entropy:.2f} bits/char (threshold: 3.0)",
                    "evidence": {
                        "avg_entropy": round(avg_entropy, 4),
                        "min_entropy": round(min_entropy, 4),
                        "sample_count": len(tokens),
                        "sample_lengths": [len(t) for t in tokens[:3]],
                    },
                    "reproducible": None,
                    "follow_up_suggested": True,
                })

    result = {
        "scanner": "token-entropy",
        "config": args.config,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Token entropy: {len(findings)} findings for {args.config}")


if __name__ == "__main__":
    main()
