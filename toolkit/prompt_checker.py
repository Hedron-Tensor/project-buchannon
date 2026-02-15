# Three-tier prompt injection protection for AI interactions
# Monitors prompts sent to AI agents to detect malicious injection attempts
#
# Key Functions:
# - check_regex_patterns() - Scan for suspicious patterns (ignore instructions, system prompts, role changes)
# - semantic_analysis() - LLM-based check for injection attempts, jailbreaks, privilege escalation
# - contextual_analysis() - Track conversation history for incremental attacks (drip-feeding sensitive info)
# - get_threat_score() - Return risk level (low/medium/high/critical)
# - block_or_warn() - Action handler based on threat level (admin-configurable)
#
# Modes:
# - Dev Mode: Log suspicious patterns for code security review
# - User Mode: Detect malicious actors attempting to manipulate AI behavior
#
# Performance: Async analysis, optional kill switch (admin-controlled)