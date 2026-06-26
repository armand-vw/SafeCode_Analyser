import re
from backend.models.schemas import Finding

CRYPTO_CHECKS = [
    (
        r"\bmd5\b",
        "high", "SAFECODE-CRYPTO-001",
        "MD5 hashing algorithm detected — cryptographically broken",
        "Use SHA-256 or SHA-3 for hashing. MD5 is vulnerable to collision attacks."
    ),
    (
        r"\bsha1\b",
        "medium", "SAFECODE-CRYPTO-002",
        "SHA-1 hashing algorithm detected — deprecated for security use",
        "Upgrade to SHA-256 or SHA-3. SHA-1 is vulnerable to collision attacks."
    ),
    (
        r"\bDES\b",
        "high", "SAFECODE-CRYPTO-003",
        "DES encryption detected — key size too small",
        "Use AES-256 instead. DES has a 56-bit key that is trivially brute-forced."
    ),
    (
        r"\bRC4\b",
        "high", "SAFECODE-CRYPTO-004",
        "RC4 cipher detected — cryptographically broken",
        "Replace with AES-GCM or ChaCha20-Poly1305."
    ),
    (
        r"\bECB\b",
        "medium", "SAFECODE-CRYPTO-005",
        "ECB cipher mode detected — leaks data patterns",
        "Use CBC, GCM, or CTR mode instead. ECB is not semantically secure."
    ),
    (
        r"Math\.random\b",
        "medium", "SAFECODE-CRYPTO-006",
        "Math.random() used — not cryptographically secure",
        "Use crypto.getRandomValues() in browser or crypto.randomBytes() in Node.js."
    ),
    (
        r"\brandom\.(?:random|randint|choice|shuffle)\b",
        "medium", "SAFECODE-CRYPTO-007",
        "Insecure random number generator used (random module in Python)",
        "Use the secrets module or os.urandom() for cryptographic randomness."
    ),
    (
        r"\brand\(\)",
        "low", "SAFECODE-CRYPTO-008",
        "rand() used — not cryptographically secure",
        "Use a CSPRNG (Cryptographically Secure PRNG) instead."
    ),
    (
        r"\b3DES\b",
        "medium", "SAFECODE-CRYPTO-009",
        "3DES/Triple DES detected — deprecated, consider migrating",
        "Migrate to AES-256. 3DES is being phased out by NIST."
    ),
    (
        r"\bBlowfish\b",
        "low", "SAFECODE-CRYPTO-010",
        "Blowfish cipher detected — 64-bit block size limits security",
        "Consider AES or ChaCha20 for modern applications."
    ),
]


def check_crypto(code: str, lines: list[str]) -> list[Finding]:
    findings = []
    for pattern, severity, rule_id, message, recommendation in CRYPTO_CHECKS:
        for i, line in enumerate(lines):
            m = re.search(pattern, line)
            if m:
                line_num = i + 1
                findings.append(Finding(
                    severity=severity,
                    rule_id=rule_id,
                    message=message,
                    line=line_num,
                    snippet=line.strip(),
                    recommendation=recommendation,
                ))
    return findings
