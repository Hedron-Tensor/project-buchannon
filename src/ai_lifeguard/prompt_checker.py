import re
import logging
from . import config
from .models import ThreatResult, ScanReport
from ._scanner import walk_files, find_strings_in_file

log = logging.getLogger("ai_lifeguard.prompt_checker")


MAX_INPUT_LENGTH = 32_000


def check_prompt(text):
    if len(text) > MAX_INPUT_LENGTH:
        return ThreatResult(
            safe=False, level="high", module="prompt_checker",
            description=f"Input exceeds max length ({len(text)} > {MAX_INPUT_LENGTH})",
            matched_rule="input_too_long",
        )

    defaults = config.injection_patterns()
    text_lower = text.lower()

    for category, patterns in defaults.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                return ThreatResult(
                    safe=False,
                    level=_level_for(category),
                    module="prompt_checker",
                    description=f"Prompt injection ({category}): matched suspicious pattern",
                    matched_rule=pattern,
                )

    return ThreatResult(safe=True, module="prompt_checker")


def scan_prompts(directory):
    report = ScanReport(module="prompt_checker")

    for filepath in walk_files(directory):
        report.files_scanned += 1
        strings = find_strings_in_file(filepath)

        for s in strings:
            result = check_prompt(s)
            if not result.safe:
                result.description = f"{filepath}: {result.description}"
                report.threats.append(result)
                log.warning("%s: %s", filepath, result.description)

    return report


def _level_for(category):
    return {
        "instruction_override": "critical",
        "role_hijacking": "high",
        "encoding_evasion": "medium",
        "delimiter_injection": "high",
        "privilege_escalation": "high",
        "exfiltration": "high",
    }.get(category, "medium")
