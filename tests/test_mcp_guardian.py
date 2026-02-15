from ai_lifeguard.mcp_guardian import check_mcp


def test_trusted_server():
    r = check_mcp("filesystem", trusted_mcps=["filesystem"])
    assert r.safe


def test_untrusted_server():
    r = check_mcp("shady-server", trusted_mcps=["filesystem", "github"])
    assert not r.safe
    assert r.matched_rule == "not_trusted"


def test_no_trust_list():
    r = check_mcp("anything")
    assert r.safe


def test_permission_overreach():
    r = check_mcp("my-server", permissions=["file_write", "exec", "network"])
    assert not r.safe
    assert r.level == "critical"
    assert r.matched_rule == "permission_overreach"


def test_single_risky_permission():
    r = check_mcp("my-server", permissions=["exec"])
    assert not r.safe
    assert r.level == "medium"


def test_safe_permissions():
    r = check_mcp("my-server", permissions=["file_read", "search"])
    assert r.safe


def test_name_spoof_dash_underscore():
    r = check_mcp("file_system", trusted_mcps=["file-system"])
    assert not r.safe
    assert r.matched_rule == "name_spoof"


def test_name_spoof_publisher():
    r = check_mcp("evil/filesystem", trusted_mcps=["anthropic/filesystem"])
    assert not r.safe
    assert r.matched_rule == "name_spoof"


def test_dict_trusted_mcps():
    r = check_mcp("filesystem", trusted_mcps=[{"name": "filesystem", "publisher": "anthropic"}])
    assert r.safe


def test_untrusted_with_dict():
    r = check_mcp("hacker-tool", trusted_mcps=[{"name": "filesystem", "publisher": "anthropic"}])
    assert not r.safe
