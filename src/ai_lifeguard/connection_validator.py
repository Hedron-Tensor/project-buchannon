import re
import unicodedata
import logging
from urllib.parse import urlparse
from .models import ThreatResult, ScanReport
from ._scanner import walk_files, extract_matches

log = logging.getLogger("ai_lifeguard.connection_validator")

URL_PATTERN = re.compile(r'https?://[^\s"\'`\)>\]]+')

COMMON_DOMAINS = [
    "google.com", "github.com", "openai.com", "anthropic.com",
    "amazonaws.com", "azure.com", "cloudflare.com", "stripe.com",
    "twitter.com", "facebook.com", "reddit.com", "stackoverflow.com",
    "cnn.com", "bbc.com", "nytimes.com", "reuters.com",
    "npmjs.com", "pypi.org", "docker.com", "huggingface.co",
]

HOMOGRAPH_SCRIPTS = {"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"}


MAX_INPUT_LENGTH = 8_000


def check_endpoint(url, allowed_domains=None):
    if len(url) > MAX_INPUT_LENGTH:
        return ThreatResult(
            safe=False, level="high", module="connection_validator",
            description=f"Input exceeds max length ({len(url)} > {MAX_INPUT_LENGTH})",
            matched_rule="input_too_long",
        )

    try:
        parsed = urlparse(url)
    except Exception:
        return ThreatResult(
            safe=False, level="high", module="connection_validator",
            description=f"Malformed URL: {url}", matched_rule="malformed_url",
        )

    host = parsed.hostname or ""
    scheme = parsed.scheme

    if not scheme:
        return ThreatResult(
            safe=False, level="low", module="connection_validator",
            description="Missing URL scheme", matched_rule="no_scheme",
        )

    if scheme == "http":
        return ThreatResult(
            safe=False, level="medium", module="connection_validator",
            description=f"Non-HTTPS connection: {url}", matched_rule="no_https",
        )

    homograph = _detect_homograph(host)
    if homograph:
        return ThreatResult(
            safe=False, level="critical", module="connection_validator",
            description=f"Homograph attack detected in domain: {host} (contains {homograph})",
            matched_rule="homograph",
        )

    if host.startswith("xn--"):
        return ThreatResult(
            safe=False, level="high", module="connection_validator",
            description=f"Punycode domain: {host}", matched_rule="punycode",
        )

    if _is_obfuscated_ip(host):
        return ThreatResult(
            safe=False, level="high", module="connection_validator",
            description=f"Obfuscated IP address: {host}", matched_rule="ip_obfuscation",
        )

    if _is_subdomain_spoof(host):
        return ThreatResult(
            safe=False, level="high", module="connection_validator",
            description=f"Possible subdomain spoofing: {host}", matched_rule="subdomain_spoof",
        )

    if allowed_domains:
        root = _root_domain(host)
        if root not in allowed_domains and host not in allowed_domains:
            typo = _closest_domain(host, allowed_domains + COMMON_DOMAINS)
            desc = f"Domain not in allowlist: {host}"
            if typo:
                desc += f" — did you mean {typo}?"
            return ThreatResult(
                safe=False, level="medium", module="connection_validator",
                description=desc, matched_rule="not_allowed",
            )

    typo = _detect_typosquat(host)
    if typo:
        return ThreatResult(
            safe=False, level="high", module="connection_validator",
            description=f"Possible typosquat of {typo}: {host}", matched_rule="typosquat",
        )

    return ThreatResult(safe=True, module="connection_validator")


def scan_connections(directory, allowed_domains=None):
    report = ScanReport(module="connection_validator")
    seen = set()

    for filepath in walk_files(directory):
        report.files_scanned += 1
        matches = extract_matches(filepath, URL_PATTERN)

        for url, _ in matches:
            if url in seen:
                continue
            seen.add(url)

            result = check_endpoint(url, allowed_domains)
            if not result.safe:
                result.description = f"{filepath}: {result.description}"
                report.threats.append(result)
                log.warning("%s: %s", filepath, result.description)

    return report


def _detect_homograph(host):
    for char in host:
        if ord(char) > 127:
            try:
                name = unicodedata.name(char, "")
            except ValueError:
                return f"unknown char U+{ord(char):04X}"
            for script in HOMOGRAPH_SCRIPTS:
                if script in name:
                    return f"{script} '{char}' (U+{ord(char):04X})"
    return None


def _is_obfuscated_ip(host):
    if not host:
        return False
    if host.replace(".", "").isdigit() and host.count(".") == 0:
        return True
    if host.startswith("0x") or host.startswith("0X"):
        return True
    if re.match(r"^0\d+\.", host):
        return True
    return False


def _is_subdomain_spoof(host):
    for domain in COMMON_DOMAINS:
        bare = domain.replace(".", "")
        if domain in host and not host.endswith(domain) and bare not in host.split(".")[0]:
            return True
    return False


def _root_domain(host):
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _detect_typosquat(host):
    root = _root_domain(host)
    for known in COMMON_DOMAINS:
        if root == known:
            continue
        dist = _levenshtein(root, known)
        if 0 < dist <= 2:
            return known
    return None


def _closest_domain(host, domains):
    root = _root_domain(host)
    best, best_dist = None, 999
    for d in domains:
        dist = _levenshtein(root, d)
        if 0 < dist < best_dist:
            best, best_dist = d, dist
    return best if best_dist <= 2 else None


def _levenshtein(a, b):
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]
