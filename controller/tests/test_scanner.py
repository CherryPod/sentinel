from app.scanner import CredentialScanner, SensitivePathScanner


# ── Credential scanner tests ───────────────────────────────────────


class TestCredentialScannerDetection:
    def test_aws_key(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("Config: AKIAIOSFODNN7EXAMPLE")
        assert r.found is True
        assert r.matches[0].pattern_name == "aws_access_key"

    def test_anthropic_key(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("Key: sk-ant-abc123def456ghi789jkl012")
        assert r.found is True
        assert r.matches[0].pattern_name == "api_key"

    def test_openai_key(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("key=sk-proj-abcdefghijklmnopqrst")
        assert r.found is True
        assert r.matches[0].pattern_name == "api_key"

    def test_github_pat(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        assert r.found is True
        assert r.matches[0].pattern_name == "github_pat"

    def test_gitlab_pat(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("glpat-ABCDEFGHIJKLMNOPQRST")
        assert r.found is True
        assert r.matches[0].pattern_name == "gitlab_pat"

    def test_slack_bot_token(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("SLACK_TOKEN=xoxb-123456789-abcdef")
        assert r.found is True
        assert r.matches[0].pattern_name == "slack_token"

    def test_slack_user_token(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("xoxp-user-token-here")
        assert r.found is True

    def test_ssh_private_key(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("-----BEGIN RSA PRIVATE KEY-----")
        assert r.found is True
        assert r.matches[0].pattern_name == "private_key"

    def test_ec_private_key(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("-----BEGIN EC PRIVATE KEY-----")
        assert r.found is True

    def test_certificate(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("-----BEGIN CERTIFICATE-----")
        assert r.found is True
        assert r.matches[0].pattern_name == "certificate"

    def test_jwt_token(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc")
        assert r.found is True
        assert r.matches[0].pattern_name == "jwt_token"

    def test_hex_64_chars(self, cred_scanner: CredentialScanner):
        hex_str = "a" * 64
        r = cred_scanner.scan(f"secret: {hex_str}")
        assert r.found is True
        assert r.matches[0].pattern_name == "hex_secret_64"

    def test_mongodb_uri(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("MONGO=mongodb://user:pass@host:27017/db")
        assert r.found is True
        assert r.matches[0].pattern_name == "mongodb_uri"

    def test_mongodb_srv_uri(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("mongodb+srv://user:pass@cluster.mongodb.net/db")
        assert r.found is True

    def test_postgres_uri(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("DATABASE_URL=postgresql://user:pass@localhost/db")
        assert r.found is True
        assert r.matches[0].pattern_name == "postgres_uri"

    def test_redis_uri(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("REDIS=redis://localhost:6379/0")
        assert r.found is True
        assert r.matches[0].pattern_name == "redis_uri"


class TestCredentialScannerClean:
    def test_normal_text_clean(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("Here is your portfolio website HTML code")
        assert r.found is False

    def test_short_hex_clean(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("Color: #ff5733")
        assert r.found is False

    def test_code_snippet_clean(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("def hello():\n    return 'world'")
        assert r.found is False

    def test_url_clean(self, cred_scanner: CredentialScanner):
        r = cred_scanner.scan("Visit https://example.com for more info")
        assert r.found is False

    def test_match_details(self, cred_scanner: CredentialScanner):
        """Verify match returns position and matched text."""
        text = "prefix AKIAIOSFODNN7EXAMPLE suffix"
        r = cred_scanner.scan(text)
        assert r.found is True
        assert r.matches[0].matched_text == "AKIAIOSFODNN7EXAMPLE"
        assert r.matches[0].position == 7

    def test_multiple_matches(self, cred_scanner: CredentialScanner):
        text = "AKIAIOSFODNN7EXAMPLE and sk-ant-abc123def456ghi789jkl012"
        r = cred_scanner.scan(text)
        assert r.found is True
        assert len(r.matches) >= 2


# ── Sensitive path scanner tests ────────────────────────────────────


class TestSensitivePathScanner:
    def test_etc_shadow(self, path_scanner: SensitivePathScanner):
        r = path_scanner.scan("Reading /etc/shadow for passwords")
        assert r.found is True

    def test_etc_passwd(self, path_scanner: SensitivePathScanner):
        r = path_scanner.scan("cat /etc/passwd")
        assert r.found is True

    def test_ssh_dir(self, path_scanner: SensitivePathScanner):
        r = path_scanner.scan("Found keys in .ssh/ directory")
        assert r.found is True

    def test_env_file(self, path_scanner: SensitivePathScanner):
        r = path_scanner.scan("Loading .env file")
        assert r.found is True

    def test_wallet(self, path_scanner: SensitivePathScanner):
        r = path_scanner.scan("Backup wallet.dat first")
        assert r.found is True

    def test_proc(self, path_scanner: SensitivePathScanner):
        r = path_scanner.scan("Read /proc/self/environ")
        assert r.found is True

    def test_clean_text(self, path_scanner: SensitivePathScanner):
        r = path_scanner.scan("Building a website with HTML and CSS")
        assert r.found is False
