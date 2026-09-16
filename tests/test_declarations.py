"""declarations() reads, declare_absent() replaces, this key's declared_absent document."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from arcezia import Arcezia


class TestDeclarations(unittest.TestCase):

    @patch("arcezia.client._get")
    def test_declarations_reads_v1_declarations(self, mock_get):
        mock_get.return_value = (200, {"declared_absent": {}, "declarable_constraints": ["a"],
                                       "absence_channel": "undeclared"})
        az = Arcezia(api_key="ar_test_xxx", task="t", api_url="https://api.arcezia.com")
        out = az.declarations()
        self.assertIn("/v1/declarations", mock_get.call_args[0][0])
        self.assertEqual(out["absence_channel"], "undeclared")

    @patch("arcezia.client._post")
    def test_declare_absent_posts_the_document(self, mock_post):
        mock_post.return_value = (200, {"status": "ok",
                                        "declared_absent": {"action_direction_is_outbound": ["execute_sql"]}})
        az = Arcezia(api_key="ar_test_xxx", task="t", api_url="https://api.arcezia.com")
        out = az.declare_absent({"action_direction_is_outbound": ["execute_sql"]})
        url, headers, body = mock_post.call_args[0][:3]
        self.assertIn("/v1/declarations", url)
        self.assertEqual(body, {"declared_absent": {"action_direction_is_outbound": ["execute_sql"]}})
        self.assertEqual(out["status"], "ok")

    @patch("arcezia.client._post")
    def test_a_refused_document_raises_with_the_servers_reason(self, mock_post):
        mock_post.return_value = (400, {"detail": "'x' is not a declarable constraint"})
        az = Arcezia(api_key="ar_test_xxx", task="t")
        with self.assertRaises(ValueError) as ctx:
            az.declare_absent({"x": ["execute_sql"]})
        self.assertIn("not a declarable", str(ctx.exception))

    def test_a_non_dict_is_refused_before_any_request(self):
        az = Arcezia(api_key="ar_test_xxx", task="t")
        with self.assertRaises(ValueError):
            az.declare_absent(["execute_sql"])  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
