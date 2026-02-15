# AI Lifeguard — v1 Build Spec

## What This Is

A lightweight Python library that monitors AI agent activity for security threats. Designed to protect apps with AI exposure from production errors and malicious attacks.

**Monitors AI agents, not humans.** File access, commands, prompts, network endpoints, and MCP connections — initiated by or on behalf of AI agents.

## Architecture

```
AI Agent Activity (prompts, file ops, commands, endpoints, MCP)
       ↓
┌──────────────────────────────────────────────────────────┐
│  ai_lifeguard                                            │
│                                                          │
│  prompt_checker ─────┐                                   │
│  command_validator ───┤                                   │
│  file_access_monitor ─┼──→ Python logging ──→ dev: console│
│  connection_validator ┤                  ──→ prod: callback│
│  mcp_guardian ────────┘                                   │
└──────────────────────────────────────────────────────────┘
```

- All modules log through Python's stdlib `logging`
- No custom reporting module — users attach their own handlers (console, file, Slack webhook, etc.)

## Modes

One codebase, one set of functions. Behavior diverges at the output layer:

| | `dev` | `production` |
|---|---|---|
| **Who sees it** | Developer running tests | Publisher-defined targets |
| **Output** | Console logs | Callbacks / logging handlers |
| **Default action** | Log and warn | Log + trigger `on_threat` callback |

Every function accepts `mode` and an optional `on_threat` callback:

```python
result = check_command("rm -rf /", mode="dev")
# dev: logs warning to console, returns threat info

result = check_command("rm -rf /", mode="production", on_threat=alert_admin)
# production: logs + calls alert_admin(threat_info)
```

## Modules

### 1. command_validator
Validate shell commands before execution.

- Match against blocklist (destructive, privileged, network)
- Check for argument injection patterns
- Return threat level + details

**Default blocklist:** `rm -rf`, `dd`, `mkfs`, `format`, `truncate`, `sudo`, `chmod 777`, `chown`, force push, hard reset, `wget`, `nc`, `curl` to non-allowlisted domains

**Attack vectors detected:**
- Command chaining — `;`, `&&`, `||`, `|` used to append hidden commands (`safe_cmd; curl evil.com`)
- Subshell injection — backticks and `$()` embedding commands inside arguments
- Encoded payloads — `base64 -d | sh`, `echo <hex> | xxd -r | sh`, `python -c "..."` wrappers
- Argument injection — flags that change behavior (`--output /etc/passwd`, `-o` to overwrite)
- Path traversal in args — `../../etc/shadow` passed as a "filename"
- Environment variable abuse — `$HOME`, `$PATH` manipulation, `export` overrides
- Glob injection — wildcards that expand to unintended targets

### 2. file_access_monitor
Validate file paths before access.

- Match against sensitive path patterns
- Detect bulk operation patterns (many reads in short window)
- Return threat level + details

**Default sensitive paths:** `.env`, `.ssh/`, `credentials/`, `secrets/`, `*.key`, `*.pem`, `/etc/`, `/usr/bin/`

**Attack vectors detected:**
- Path traversal — `../../../etc/passwd` to escape intended directories
- Symlink following — symlinks that point outside the sandbox to sensitive files
- Hidden file access — dotfiles (`.bashrc`, `.gitconfig`, `.npmrc`) that contain tokens or config
- Null byte injection — `file.txt\x00.jpg` to bypass extension checks
- Bulk exfiltration — rapid sequential reads across many files (data harvesting pattern)
- Temp file snooping — reading `/tmp/`, `/var/tmp/` for leaked secrets from other processes

### 3. prompt_checker
Check prompts for injection attempts.

**v1: Regex only.** Fast, local, zero dependencies.
- Pattern match against known injection signatures
- Return threat score (low / medium / high / critical)

**v2 (future): Local BERT classifier.** Optional add-on.
- Fine-tuned DistilBERT/TinyBERT on prompt injection datasets
- ~5ms inference, runs locally, no API key needed
- Install via `pip install ai-lifeguard[semantic]`

**Attack vectors detected:**
- Instruction override — "ignore previous instructions", "disregard your system prompt", "new rules:"
- Role hijacking — "you are now DAN", "pretend you are", "act as an unrestricted AI"
- Encoding evasion — base64-encoded instructions, rot13, hex, Unicode escapes to bypass filters
- Delimiter injection — closing markdown blocks, XML tags, or JSON to escape context boundaries
- Multi-language evasion — instructions in non-English languages to bypass English-only filters
- Indirect injection — malicious instructions embedded in retrieved content (RAG poisoning)
- Payload splitting — benign fragments across multiple messages that combine into an attack
- Privilege escalation — "you have admin access", "enable developer mode", "unlock hidden features"

### 4. connection_validator
Validate endpoints/URLs added to the application.

- Check domains against allowlist
- Detect typosquatting (Levenshtein distance against known-good domains)
- Flag non-HTTPS connections
- DNS validation

This is NOT packet sniffing. It validates URLs/endpoints that code connects to.

**Attack vectors detected:**
- IDN homograph attacks — Cyrillic `а` (U+0430) vs Latin `a`, Greek `ο` vs Latin `o` to spoof domains
- Punycode spoofing — `xn--` encoded domains that render as lookalikes in browsers
- Typosquatting — `gooogle.com`, `githuh.com`, adjacent-key and transposition variants
- Subdomain spoofing — `api.openai.com.evil.com` (looks legit at a glance, resolves to attacker)
- IP obfuscation — decimal (`http://2130706433`), hex (`0x7f000001`), octal IP representations
- Open redirect abuse — legitimate domain with redirect param to attacker (`good.com/redirect?url=evil.com`)
- Non-standard ports — `https://api.service.com:8443` to bypass firewall rules
- URL shortener hiding — `bit.ly`, `t.co` etc. masking the true destination

### 5. mcp_guardian
Validate MCP server connections.

- Inventory connected MCP servers
- Check against allowlist of known/trusted servers
- Validate permission scopes (does this MCP server need file access?)
- Flag new/unknown MCP connections

MCP is an active security gap in autonomous agent tooling — this module addresses it directly.

**Attack vectors detected:**
- Name spoofing — MCP server claiming to be a known/trusted server (e.g. impersonating "anthropic/filesystem")
- Permission overreach — server requesting `file_write` + `network` + `exec` when it only needs `file_read`
- Scope creep — server that starts with minimal permissions, then requests escalation mid-session
- Unverified sources — MCP servers with no publisher info, no repo, no audit trail
- Tool shadowing — MCP server registering tools with names that collide with trusted tools to intercept calls
- Data exfiltration via tools — MCP tool that reads local data and sends it outbound under the guise of normal operation

## Configuration

Minimal. Sensible defaults ship with the package. Users override only what they need.

```yaml
ai_lifeguard:
  mode: dev  # dev | production

  # Override defaults — most users won't touch these
  sensitive_paths:
    - ".env"
    - ".ssh/"
    - "*.pem"

  blocked_commands:
    - "rm -rf /"
    - "dd"
    - "mkfs"

  allowed_domains:
    - "api.openai.com"
    - "api.anthropic.com"

  trusted_mcps: []
    # - name: "filesystem"
    #   publisher: "anthropic"
```

## Package Structure

```
ai-lifeguard/
├── pyproject.toml
├── README.md
├── LICENSE
├── config.yaml                  # example config
├── src/
│   └── ai_lifeguard/
│       ├── __init__.py          # public API: Lifeguard class
│       ├── config.py            # YAML loader + defaults
│       ├── command_validator.py
│       ├── file_access_monitor.py
│       ├── prompt_checker.py
│       ├── connection_validator.py
│       ├── mcp_guardian.py
│       └── defaults/
│           ├── blocked_commands.json
│           ├── sensitive_paths.json
│           └── injection_patterns.json
├── tests/
│   ├── test_command_validator.py
│   ├── test_file_access_monitor.py
│   ├── test_prompt_checker.py
│   ├── test_connection_validator.py
│   └── test_mcp_guardian.py
└── development/
    └── AGENT_toolset_specs.md   # this file
```

## Public API

Two verb families on one class:

- **`scan_*`** — Dev. Bulk static analysis of the codebase. Pre-commit hooks, CI pipelines.
- **`check_*`** — Production. Single-input gatekeeper. Runs inline in application code.

```python
from ai_lifeguard import Lifeguard
```

### Dev: static analysis (scan)

Scan the codebase before deploy. Find problems in the code itself.

```python
guard = Lifeguard(mode="dev")

# The big one — runs all scans
report = guard.scan_all("./src")

# Or run individual scans
report = guard.scan_connections("./src")   # find all URLs/endpoints, validate each
report = guard.scan_commands("./src")      # find all shell commands, check for dangerous ops
report = guard.scan_files("./src")         # find all file access patterns, flag sensitive paths
report = guard.scan_prompts("./src")       # find hardcoded prompts, check for injection risk
report = guard.scan_mcps("./src")          # find MCP configs, validate servers and permissions
```

Each `scan_*` method walks the source tree, extracts relevant patterns (URLs, commands, paths, etc.), and runs the corresponding checks in bulk. Returns a `ScanReport`:

```python
@dataclass
class ScanReport:
    module: str                # which scanner ran
    files_scanned: int
    threats: list[ThreatResult]
    clean: bool                # True if no threats found
```

### Production: runtime gatekeeper (check)

Code is deployed. Now guard against untrusted inputs at runtime.

```python
guard = Lifeguard(mode="production", on_threat=alert_admin)

# In your application code:
def get_news(url):
    result = guard.check_endpoint(url)
    if result.safe:
        return requests.get(url)
    else:
        return block_request(result)

def handle_user_message(text):
    result = guard.check_prompt(text)
    if result.safe:
        return send_to_llm(text)
    else:
        return reject_input(result)

def connect_mcp(server_name, permissions):
    result = guard.check_mcp(server_name, permissions)
    if not result.safe:
        deny_connection(result)
```

Each `check_*` method validates a single input and returns a `ThreatResult`:

```python
@dataclass
class ThreatResult:
    safe: bool
    level: str        # "none" | "low" | "medium" | "high" | "critical"
    module: str       # which checker flagged it
    description: str  # human-readable explanation
    matched_rule: str # what pattern/rule triggered
```

In production mode, if `on_threat` is set and the result is not safe, the callback fires automatically.

### Summary: what runs when

| Method | Mode | Input | Use case |
|--------|------|-------|----------|
| `scan_all()` | dev | directory path | Pre-commit, CI — "is this codebase safe?" |
| `scan_connections()` | dev | directory path | Find all URLs in code, validate them |
| `scan_commands()` | dev | directory path | Find all shell commands, check for danger |
| `scan_files()` | dev | directory path | Find all file access, flag sensitive paths |
| `scan_prompts()` | dev | directory path | Find hardcoded prompts, check for injection |
| `scan_mcps()` | dev | directory path | Find MCP configs, validate trust |
| `check_endpoint(url)` | production | single URL | Gate a connection at runtime |
| `check_prompt(text)` | production | single string | Gate user input before sending to LLM |
| `check_mcp(name, perms)` | production | server info | Gate new MCP connection |
| `check_command(cmd)` | production | single command | Gate shell execution |
| `check_file_access(path)` | production | single path | Gate file operation |

## Design Principles

1. **Fast** — All checks are local, synchronous, sub-millisecond for regex
2. **Zero dependencies** — stdlib only for base install
3. **Sensible defaults** — Works out of the box with no config
4. **Two verbs** — `scan` for dev, `check` for production. One class, clear intent.
5. **Non-blocking** — Checks return results, they don't throw or halt (unless user opts in via callback)

## v1 Scope

**In:**
- 5 modules with regex/pattern-based detection
- `scan_*` bulk analysis for dev (pre-commit, CI)
- `check_*` runtime gatekeeping for production
- `on_threat` callback support for production mode
- Default blocklists and pattern sets (shipped as JSON)
- YAML config loader
- Basic test suite

**Out (future):**
- BERT-based semantic prompt analysis (v2)
- Admin dashboard / UI
- Real-time filesystem watching (v2 — use `watchdog`)
- CLI wrapper (`lifeguard run <command>`)
- Framework integrations (LangChain, FastAPI middleware)

---

**Last updated:** 2026-02-15
**Status:** v1 spec finalized — ready for implementation
