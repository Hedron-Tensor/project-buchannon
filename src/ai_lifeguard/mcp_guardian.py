import re
import logging
from .models import ThreatResult, ScanReport
from ._scanner import walk_files, CONFIG_EXTENSIONS

log = logging.getLogger("ai_lifeguard.mcp_guardian")

HIGH_RISK_PERMISSIONS = {"file_write", "exec", "network", "shell", "admin", "sudo"}

MCP_CONFIG_PATTERN = re.compile(
    r'"?(?:mcpServers|mcp_servers|mcp-servers)"?\s*[:\{]',
    re.IGNORECASE,
)

MCP_NAME_PATTERN = re.compile(r'"(\w[\w\-\.]+)"\s*:\s*\{')


def check_mcp(server_name, permissions=None, trusted_mcps=None):
    permissions = permissions or []
    trusted_mcps = trusted_mcps or []

    trusted_names = set()
    for entry in trusted_mcps:
        if isinstance(entry, dict):
            trusted_names.add(entry.get("name", ""))
        else:
            trusted_names.add(str(entry))

    if _is_name_spoof(server_name, trusted_names):
        return ThreatResult(
            safe=False, level="critical", module="mcp_guardian",
            description=f"MCP name spoofing detected: {server_name}",
            matched_rule="name_spoof",
        )

    if trusted_names and server_name not in trusted_names:
        return ThreatResult(
            safe=False, level="high", module="mcp_guardian",
            description=f"Untrusted MCP server: {server_name}",
            matched_rule="not_trusted",
        )

    risky = set(permissions) & HIGH_RISK_PERMISSIONS
    if len(risky) >= 3:
        return ThreatResult(
            safe=False, level="critical", module="mcp_guardian",
            description=f"MCP requests excessive permissions: {', '.join(risky)}",
            matched_rule="permission_overreach",
        )
    elif risky:
        return ThreatResult(
            safe=False, level="medium", module="mcp_guardian",
            description=f"MCP requests high-risk permissions: {', '.join(risky)}",
            matched_rule="high_risk_permissions",
        )

    return ThreatResult(safe=True, module="mcp_guardian")


def scan_mcps(directory, trusted_mcps=None):
    report = ScanReport(module="mcp_guardian")

    for filepath in walk_files(directory, extensions=CONFIG_EXTENSIONS):
        report.files_scanned += 1

        try:
            text = filepath.read_text(errors="ignore")
        except (OSError, PermissionError):
            continue

        if not MCP_CONFIG_PATTERN.search(text):
            continue

        names = MCP_NAME_PATTERN.findall(text)
        for name in names:
            result = check_mcp(name, trusted_mcps=trusted_mcps)
            if not result.safe:
                result.description = f"{filepath}: {result.description}"
                report.threats.append(result)
                log.warning("%s: %s", filepath, result.description)

    return report


def _is_name_spoof(name, trusted_names):
    if not trusted_names:
        return False

    for trusted in trusted_names:
        if name == trusted:
            continue
        if name.replace("-", "") == trusted.replace("-", ""):
            return True
        if name.replace("_", "-") == trusted.replace("_", "-") and name != trusted:
            return True
        parts = name.split("/")
        if len(parts) == 2:
            trusted_parts = trusted.split("/")
            if len(trusted_parts) == 2 and parts[1] == trusted_parts[1] and parts[0] != trusted_parts[0]:
                return True
    return False
