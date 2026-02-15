# AGENT: Project Buchannon Toolset Specifications

## Overview
Project Buchannon is an AI safety and code security audit toolkit designed to monitor AI agent activity and ensure built code security. This is NOT a developer activity monitor - it focuses exclusively on AI interactions and code security.

## Core Philosophy

### What We Monitor
1. **AI Agent Activity** - All operations performed by AI agents (file access, commands, network, prompts)
2. **Built Code Security** - Security analysis of generated/deployed code

### What We DON'T Monitor
- ❌ Human developer typing/editing code
- ❌ Human developer terminal commands
- ❌ Human developer workflow/IDE activity
- ❌ Human developer file operations

### Operational Principles
- **Audit-First Approach** - Primary purpose is logging and monitoring, not blocking
- **Async Performance** - No interference with build/dev workflow
- **Optional Kill Switch** - Admin-controlled, last resort only
- **Dual-Mode Operation** - Dev mode (code security) + User mode (malicious activity detection)

---

## Tool Specifications

### 1. prompt_checker.py
**Purpose:** Three-tier prompt injection protection

**Monitors:**
- Regex patterns for injection attempts
- LLM semantic analysis for jailbreaks
- Contextual conversation analysis for incremental attacks

**Dev Mode:** Log suspicious patterns in prompts for security review
**User Mode:** Detect malicious actors manipulating AI behavior

---

### 2. connection_sniffer.py
**Purpose:** Network connection monitoring

**Monitors:**
- Active network connections by AI/code
- Allowlist verification for domains/IPs
- Traffic pattern anomalies

**Dev Mode:** Log when AI connects to unverified endpoints
**User Mode:** Detect data exfiltration or unauthorized network activity

---

### 3. mcp_guardian.py
**Purpose:** MCP connection validation

**Monitors:**
- Active MCP connections
- MCP authorship and permissions
- New connections created by AI tools

**Dev Mode:** Warn when connecting to unverified MCPs
**User Mode:** Detect MCPs attempting unauthorized access

---

### 4. messaging_reporting.py
**Purpose:** Centralized reporting system

**Functions:**
- Aggregate logs from all tools
- Route alerts based on severity
- Scheduled summaries and emergency notifications

**Integration:** Hub for all Buchannon tool events

---

### 5. file_access_monitor.py
**Purpose:** File system operation tracking

**Monitors:**
- AI agent file read/write/delete operations
- Access to sensitive paths (.env, .ssh, credentials)
- Bulk file operations (exfiltration attempts)

**Dev Mode:** Log when AI-generated code accesses sensitive paths
**User Mode:** Detect malicious file access patterns

**Protected Paths:**
- `.env`, `.ssh/`, `credentials/`, `secrets/`, `*.key`, `*.pem`
- `/etc/`, `/usr/bin/`, `/System/`

---

### 6. command_validator.py
**Purpose:** Shell command monitoring

**Monitors:**
- Commands executed by AI agents
- Dangerous operations (rm -rf, dd, mkfs)
- Privileged commands (sudo, git force operations)

**Dev Mode:** Log when AI-generated code includes risky commands
**User Mode:** Detect malicious command execution

**Monitored Commands:**
- Destructive: `rm -rf`, `dd`, `mkfs`, `format`
- Network: `curl` to non-allowlisted domains, `wget`, `nc`
- Privileged: `sudo`, `chmod 777`, `chown`

---

## Configuration Strategy

### config.yaml Structure
```yaml
buchannon:
  enabled: true
  mode: dev  # dev | user | both
  
  allowlists:
    domains: []
    ips: []
    mcps: []
    paths: []
  
  blocklists:
    commands: []
    paths: []
    patterns: []
  
  kill_switch:
    enabled: false  # Admin-controlled
    auto_block: false
  
  reporting:
    channels: []  # email, slack, webhook
    routine_schedule: daily
    alert_threshold: medium
```

---

## Architecture

```
AI Agent Activity
       ↓
[prompt_checker] [connection_sniffer] [mcp_guardian] [file_access_monitor] [command_validator]
       ↓                ↓                    ↓                  ↓                    ↓
                            [messaging_reporting]
                                     ↓
                              Administrator
```

---

## Implementation Guidelines

1. **Standalone Modules** - Each tool runs independently
2. **Function-Based Design** - Simple functions, minimal classes
3. **Minimal Dependencies** - Standard library preferred
4. **Async Logging** - Non-blocking operations
5. **Fail-Safe Defaults** - Log when uncertain, block only if admin-enabled
6. **Clear Audit Trail** - Structured JSON logs with timestamps

---

## Terminology

- **Allowlist/Blocklist** - NOT whitelist/blacklist
- **AI Agent** - Any AI system interacting with code/system
- **Dev Mode** - Code security audit focus
- **User Mode** - Malicious activity detection focus
- **Kill Switch** - Optional admin-controlled blocking mechanism

---

## Next Steps

1. Implement core monitoring functions for each tool
2. Build config.yaml parser
3. Integrate messaging_reporting as central hub
4. Add async logging infrastructure
5. Create admin dashboard for kill switch control
6. Write tests for each tool module

---

**Document Created:** 2026-02-15
**Status:** Specifications Complete - Ready for Implementation

