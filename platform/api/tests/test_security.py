import asyncio
import hashlib
import hmac
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ["DATABASE_URL"] = "postgresql://test:test@localhost/test"
os.environ["PLATFORM_API_KEY"] = "a" * 64
os.environ["GITHUB_WEBHOOK_SECRET"] = "b" * 64
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main
from starlette.requests import Request
from starlette.responses import Response


class SecurityValidationTests(unittest.TestCase):
    def test_accepts_matching_github_clone_url(self):
        main.validate_github_repo(
            "owner/repository", "https://github.com/owner/repository.git"
        )

    def test_rejects_non_github_clone_url(self):
        with self.assertRaises(ValueError):
            main.validate_github_repo(
                "owner/repository", "https://example.com/owner/repository.git"
            )

    def test_rejects_branch_path_traversal(self):
        with self.assertRaises(ValueError):
            main.validate_branch("../main")

    def test_verifies_github_sha256_signature(self):
        body = b'{"ref":"refs/heads/main"}'
        signature = "sha256=" + hmac.new(
            main.GITHUB_WEBHOOK_SECRET.encode(), body, hashlib.sha256
        ).hexdigest()

        self.assertTrue(main.verify_github_signature(body, signature))
        self.assertFalse(main.verify_github_signature(body, "sha256=invalid"))

    def test_protects_api_routes_with_api_key(self):
        async def verify():
            request = Request({
                "type": "http",
                "method": "GET",
                "path": "/api/stats",
                "headers": [],
                "query_string": b"",
                "server": ("testserver", 80),
                "client": ("testclient", 1234),
                "scheme": "http",
                "http_version": "1.1",
            })

            async def next_response(_request):
                return Response("ok")

            denied = await main.require_api_key(request, next_response)
            self.assertEqual(denied.status_code, 401)

            request = Request({
                "type": "http",
                "method": "GET",
                "path": "/api/stats",
                "headers": [(b"x-api-key", main.PLATFORM_API_KEY.encode())],
                "query_string": b"",
                "server": ("testserver", 80),
                "client": ("testclient", 1234),
                "scheme": "http",
                "http_version": "1.1",
            })
            allowed = await main.require_api_key(request, next_response)
            self.assertEqual(allowed.status_code, 200)

        asyncio.run(verify())


class ScannerFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_sectl_failure_is_not_reported_as_clean(self):
        failed_process = SimpleNamespace(returncode=1, stderr="scanner unavailable")
        with patch("main.subprocess.run", return_value=failed_process):
            with self.assertRaisesRegex(RuntimeError, "scanner unavailable"):
                await main.run_sectl(1, ".", "k8s")

    async def test_gitleaks_failure_is_not_reported_as_clean(self):
        failed_process = SimpleNamespace(returncode=1, stderr="docker unavailable")
        with patch("main.subprocess.run", return_value=failed_process):
            with self.assertRaisesRegex(RuntimeError, "docker unavailable"):
                await main.run_gitleaks(1, ".")


if __name__ == "__main__":
    unittest.main()
