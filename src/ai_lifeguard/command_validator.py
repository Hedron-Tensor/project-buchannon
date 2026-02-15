import re
import logging
from . import config
from .models import ThreatResult, ScanReport
from ._scanner import walk_files, extract_matches

log = logging.getLogger("ai_lifeguard.command_validator")

CMD_SOURCE_PATTERNS = re.compile(
    r'subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(\s*["\']([^"\']+)["\']'
    r'|os\.(?:system|popen)\s*\(\s*["\']([^"\']+)["\']'
    r'|exec\s*\(\s*["\']([^"\']+)["\']',
)


def check_command(cmd, allowed_commands=None):
    defaults = config.blocked_commands()

    for category, patterns in defaults.items():
        if category == "chaining":
            continue

        for pattern in patterns:
            if re.search(pattern, cmd, re.IGNORECASE):
                return ThreatResult(
                    safe=False,
                    level=_level_for(category),
                    module="command_validator",
                    description=f"Blocked {category} pattern in command",
                    matched_rule=pattern,
                )

    chaining = defaults.get("chaining", [])
    for sep in chaining:
        if re.search(sep, cmd):
            parts = re.split(r'[;&|]+', cmd)
            if len(parts) > 1:
                for part in parts:
                    sub = check_command(part.strip(), allowed_commands)
                    if not sub.safe:
                        return ThreatResult(
                            safe=False,
                            level=sub.level,
                            module="command_validator",
                            description=f"Dangerous command hidden via chaining: {sub.description}",
                            matched_rule=sub.matched_rule,
                        )
                return ThreatResult(
                    safe=True,
                    level="low",
                    module="command_validator",
                    description="Command uses chaining — review manually",
                    matched_rule="chaining",
                )

    if allowed_commands and cmd.split()[0] not in allowed_commands:
        return ThreatResult(
            safe=False,
            level="medium",
            module="command_validator",
            description=f"Command not in allowlist: {cmd.split()[0]}",
            matched_rule="allowlist",
        )

    return ThreatResult(safe=True, module="command_validator")


def scan_commands(directory):
    report = ScanReport(module="command_validator")

    for filepath in walk_files(directory):
        report.files_scanned += 1
        matches = extract_matches(filepath, CMD_SOURCE_PATTERNS)

        for match_text, _ in matches:
            groups = CMD_SOURCE_PATTERNS.search(match_text)
            if not groups:
                continue
            cmd = next((g for g in groups.groups() if g), None)
            if not cmd:
                continue

            result = check_command(cmd)
            if not result.safe:
                result.description = f"{filepath}:{result.description}"
                report.threats.append(result)
                log.warning("%s: %s", filepath, result.description)

    return report


def _level_for(category):
    return {
        "destructive": "critical",
        "privileged": "high",
        "network": "medium",
        "git_dangerous": "high",
        "injection": "critical",
    }.get(category, "medium")
