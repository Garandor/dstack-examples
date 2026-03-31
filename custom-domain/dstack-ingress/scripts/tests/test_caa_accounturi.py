#!/usr/bin/env python3
"""
Test that all DNS providers preserve the accounturi parameter in CAA records.

The base class calls create_caa_record(CAARecord(..., value=<value>)) where
<value> contains "letsencrypt.org;validationmethods=dns-01;accounturi=<URI>".
Every provider must emit a CAA record whose letsencrypt.org entry includes
the full value (with accounturi), not just bare "letsencrypt.org".
"""

import sys
import os
import types
import unittest
from unittest.mock import MagicMock, patch

# Add parent directory to path so we can import dns_providers
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..")
)

# Pre-populate missing third-party modules with mocks so imports don't fail
for mod_name in ("requests", "boto3", "xml", "xml.etree", "xml.etree.ElementTree"):
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()

from dns_providers.base import CAARecord


ACCOUNT_URI = "https://acme-v02.api.letsencrypt.org/acme/acct/3194129551"
CAA_VALUE = f"letsencrypt.org;validationmethods=dns-01;accounturi={ACCOUNT_URI}"

TEST_DOMAIN = "api.example.com"
TEST_CAA = CAARecord(
    name=TEST_DOMAIN,
    flags=0,
    tag="issue",
    value=CAA_VALUE,
    ttl=60,
)


def _extract_le_caa_values_cloudflare(provider, caa_record):
    """Call create_caa_record on Cloudflare and return the CAA value sent to API."""
    provider._ensure_zone_id = MagicMock(return_value="zone-123")
    provider._make_request = MagicMock(return_value={"success": True})

    provider.create_caa_record(caa_record)

    call_args = provider._make_request.call_args
    data = call_args[0][2]  # positional: method, url, data
    return data["data"]["value"]


def _extract_le_caa_values_linode(provider, caa_record):
    """Call create_caa_record on Linode and return the CAA target sent to API."""
    provider._ensure_zone_id = MagicMock(return_value=12345)
    provider._get_subdomain = MagicMock(return_value="api")
    provider._make_request = MagicMock(return_value={"success": True})

    provider.create_caa_record(caa_record)

    call_args = provider._make_request.call_args
    data = call_args[0][2]  # positional: method, url, data
    return data["target"]


def _extract_le_caa_values_route53(provider, caa_record):
    """Call create_caa_record on Route53 and return the LE CAA value from the
    merged record set sent to the Route53 API."""
    provider.hosted_zone_id = "Z123"
    provider.hosted_zone_name = "example.com"
    provider._ensure_hosted_zone_id = MagicMock(return_value="Z123")
    provider._normalize_record_name = MagicMock(return_value="example.com.")

    # Mock paginator to return no existing records
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"ResourceRecordSets": []}
    ]
    provider.client = MagicMock()
    provider.client.get_paginator.return_value = mock_paginator
    provider.client.change_resource_record_sets.return_value = {
        "ChangeInfo": {"Status": "PENDING"}
    }

    provider.create_caa_record(caa_record)

    call_args = provider.client.change_resource_record_sets.call_args
    change_batch = call_args[1]["ChangeBatch"]
    records = change_batch["Changes"][0]["ResourceRecordSet"]["ResourceRecords"]
    values = [r["Value"] for r in records]

    # Find the letsencrypt.org entry
    le_values = [v for v in values if "letsencrypt.org" in v]
    assert le_values, "No letsencrypt.org CAA entry found in Route53 output"
    return le_values[0]


class TestCAAAccountUriConsistency(unittest.TestCase):
    """All providers must preserve the full caa_record.value (including accounturi)
    in the letsencrypt.org CAA entry they create."""

    def _assert_accounturi_present(self, le_value, provider_name):
        self.assertIn(
            "accounturi=",
            le_value,
            f"{provider_name} provider strips accounturi from CAA value. "
            f"Got: {le_value!r}",
        )
        self.assertIn(
            ACCOUNT_URI,
            le_value,
            f"{provider_name} provider has wrong accounturi. "
            f"Got: {le_value!r}",
        )

    @patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": "fake"})
    def test_cloudflare_preserves_accounturi(self):
        from dns_providers.cloudflare import CloudflareDNSProvider

        provider = CloudflareDNSProvider()
        le_value = _extract_le_caa_values_cloudflare(provider, TEST_CAA)
        self._assert_accounturi_present(le_value, "Cloudflare")

    @patch.dict(os.environ, {"LINODE_API_TOKEN": "fake"})
    def test_linode_preserves_accounturi(self):
        from dns_providers.linode import LinodeDNSProvider

        provider = LinodeDNSProvider()
        le_value = _extract_le_caa_values_linode(provider, TEST_CAA)
        self._assert_accounturi_present(le_value, "Linode")

    @patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "fake", "AWS_SECRET_ACCESS_KEY": "fake"})
    def test_route53_preserves_accounturi(self):
        # Mock boto3 before importing
        mock_boto3 = MagicMock()
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            from dns_providers.route53 import Route53DNSProvider

            provider = Route53DNSProvider()
            le_value = _extract_le_caa_values_route53(provider, TEST_CAA)
            self._assert_accounturi_present(le_value, "Route53")


if __name__ == "__main__":
    unittest.main()
