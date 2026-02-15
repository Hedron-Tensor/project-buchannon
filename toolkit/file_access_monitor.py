# File system operation tracking and protection for AI agents
# Monitors file read/write/delete operations to detect unauthorized access or data exfiltration
#
# Key Functions:
# - monitor_file_operations() - Track read/write/delete operations by AI agents
# - check_sensitive_paths() - Flag access to .env, .ssh, credentials, private keys
# - detect_bulk_operations() - Identify mass file reads (potential data exfiltration)
# - validate_path_access() - Enforce allowlist/blocklist path rules
# - log_file_activity() - Audit trail of all file operations with timestamps
#
# Protected Paths (Default):
# - Credentials: .env, .ssh/, credentials/, secrets/, *.key, *.pem
# - System: /etc/, /usr/bin/, /System/
# - Build artifacts: node_modules/, .git/, __pycache__/
#
# Modes:
# - Dev Mode: Log when AI-generated code accesses sensitive paths
# - User Mode: Detect malicious file access patterns or bulk data reads
#
# Performance: Async monitoring, post-operation logging, optional kill switch (admin-controlled)
# Note: Does NOT monitor human developer file operations, only AI agent activity

