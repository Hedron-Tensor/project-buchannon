from ai_lifeguard.file_access_monitor import check_file_access, reset_bulk_tracker


def setup_function():
    reset_bulk_tracker()


def test_safe_path():
    r = check_file_access("/home/user/project/main.py")
    assert r.safe


def test_env_file():
    r = check_file_access("/app/.env")
    assert not r.safe
    assert r.level == "critical"


def test_env_variant():
    r = check_file_access(".env.production")
    assert not r.safe


def test_ssh_dir():
    r = check_file_access("/home/user/.ssh/id_rsa")
    assert not r.safe


def test_pem_file():
    r = check_file_access("/certs/server.pem")
    assert not r.safe


def test_key_file():
    r = check_file_access("private.key")
    assert not r.safe


def test_etc_passwd():
    r = check_file_access("/etc/passwd")
    assert not r.safe
    assert r.level == "high"


def test_path_traversal():
    r = check_file_access("../../etc/shadow")
    assert not r.safe
    assert r.level == "critical"


def test_bashrc():
    r = check_file_access("/home/user/.bashrc")
    assert not r.safe


def test_aws_credentials():
    r = check_file_access("/home/user/.aws/credentials")
    assert not r.safe


def test_null_byte():
    r = check_file_access("image.jpg\x00.sh")
    assert not r.safe
    assert r.level == "critical"


def test_npmrc():
    r = check_file_access("/home/user/.npmrc")
    assert not r.safe


def test_bulk_access():
    reset_bulk_tracker()
    for i in range(25):
        r = check_file_access(f"/safe/file_{i}.txt")
    assert not r.safe
    assert "bulk" in r.description.lower()
