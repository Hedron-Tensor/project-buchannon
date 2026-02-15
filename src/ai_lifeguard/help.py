HELP_TEXT = """
AI Lifeguard v0.1.0
====================

Two modes, one class:

  guard = Lifeguard(mode="dev")           # scan code before deploy
  guard = Lifeguard(mode="production")    # guard inputs at runtime

Dev — scan your codebase:

  guard.scan_all("./src")          Run all scanners
  guard.scan_commands("./src")     Find dangerous shell commands
  guard.scan_files("./src")        Find sensitive file access
  guard.scan_prompts("./src")      Find prompt injection risks
  guard.scan_connections("./src")  Find suspicious URLs/endpoints
  guard.scan_mcps("./src")         Find untrusted MCP configs

Production — check individual inputs:

  guard.check_command(cmd)              Validate a shell command
  guard.check_file_access(path)         Validate a file path
  guard.check_prompt(text)              Check for prompt injection
  guard.check_endpoint(url)             Validate a URL/endpoint
  guard.check_mcp(name, permissions)    Validate an MCP connection

Every method returns a ThreatResult:

  result.safe          bool — True if no threat detected
  result.level         "none" | "low" | "medium" | "high" | "critical"
  result.module        Which checker flagged it
  result.description   What was found
  result.matched_rule  Which pattern triggered

Production callbacks:

  def alert(result):
      send_slack(result.description)

  guard = Lifeguard(mode="production", on_threat=alert)

Config:

  guard = Lifeguard.from_config("config.yaml")   # or .json

Docs: https://github.com/anthropics/ai-lifeguard
""".strip()


def show_help():
    print(HELP_TEXT)
