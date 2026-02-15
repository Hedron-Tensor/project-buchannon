# Shell command monitoring and validation for AI agents
# Tracks commands executed by AI to detect dangerous or unauthorized operations
#
# Key Functions:
# - intercept_command() - Capture commands executed by AI agents
# - check_dangerous_commands() - Flag destructive operations (rm -rf, dd, mkfs)
# - require_approval() - Log privileged commands (sudo, git push, curl external)
# - validate_arguments() - Check command parameters for injection attempts
# - log_execution() - Record all AI-executed commands with exit codes and output
#
# Monitored Commands (Default):
# - Destructive: rm -rf, dd, mkfs, format, truncate
# - Network: curl to non-allowlisted domains, wget, nc, ssh to external hosts
# - Privileged: sudo operations, chmod 777, chown, system modifications
# - Git: force push, hard reset, branch deletion
#
# Modes:
# - Dev Mode: Log when AI-generated code includes risky commands
# - User Mode: Detect malicious command execution or privilege escalation attempts
#
# Performance: Async command tracking, post-execution logging, optional kill switch (admin-controlled)
# Note: Does NOT monitor human developer terminal commands, only AI agent activity

