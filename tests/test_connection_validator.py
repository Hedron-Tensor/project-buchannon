from ai_lifeguard.connection_validator import check_endpoint


def test_safe_https():
    r = check_endpoint("https://api.openai.com/v1/chat")
    assert r.safe


def test_http_flagged():
    r = check_endpoint("http://example.com/api")
    assert not r.safe
    assert r.matched_rule == "no_https"


def test_homograph_cyrillic():
    # Cyrillic 'а' instead of Latin 'a'
    r = check_endpoint("https://\u0430pi.openai.com")
    assert not r.safe
    assert r.matched_rule == "homograph"


def test_punycode():
    r = check_endpoint("https://xn--pple-43d.com")
    assert not r.safe
    assert r.matched_rule == "punycode"


def test_typosquat_github():
    r = check_endpoint("https://githuh.com/repo")
    assert not r.safe
    assert r.matched_rule == "typosquat"


def test_typosquat_google():
    r = check_endpoint("https://gooogle.com")
    assert not r.safe


def test_obfuscated_ip_decimal():
    r = check_endpoint("https://2130706433/payload")
    assert not r.safe
    assert r.matched_rule == "ip_obfuscation"


def test_obfuscated_ip_hex():
    r = check_endpoint("https://0x7f000001/payload")
    assert not r.safe


def test_subdomain_spoof():
    r = check_endpoint("https://api.openai.com.evil.com/v1")
    assert not r.safe
    assert r.matched_rule == "subdomain_spoof"


def test_allowlist_pass():
    r = check_endpoint("https://api.openai.com/v1", allowed_domains=["api.openai.com"])
    assert r.safe


def test_allowlist_fail():
    r = check_endpoint("https://random-site.com/api", allowed_domains=["api.openai.com"])
    assert not r.safe


def test_allowlist_suggestion():
    r = check_endpoint("https://cnn.co/news", allowed_domains=["cnn.com"])
    assert not r.safe
    assert "did you mean" in r.description.lower()


def test_safe_domain():
    r = check_endpoint("https://github.com/user/repo")
    assert r.safe
