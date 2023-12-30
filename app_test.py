import base64
import re
import unittest

import responses
import os
import json

TEST_DOMAIN = "example.com"
TEST_PASSWORD = "password"
TEST_IP4 = "127.0.0.1"
TEST_IP6 = "::1"

AUTH_HEADER = {
    "Authorization": "Basic "
    + base64.b64encode(f"{TEST_DOMAIN}:{TEST_PASSWORD}".encode()).decode()
}
IP4_DATA = {"hostname": TEST_DOMAIN, "myip": TEST_IP4}
IP6_DATA = {"hostname": TEST_DOMAIN, "myip6": TEST_IP6}

DNSIMPLE_ZONE_ID = 1
DNSIMPLE_RECORD_ID = 1

os.environ["AUTHENTICATION"] = json.dumps({TEST_DOMAIN: TEST_PASSWORD})
os.environ["DNSIMPLE_ACCOUNT_ID"] = "1234"
os.environ["DNSIMPLE_API_KEY"] = "secret"

from app import app


class WebhookTests(unittest.TestCase):
    @staticmethod
    def _stub_zone_response():
        return responses.add(
            method="GET",
            url=re.compile(
                f"https://api\\.dnsimple\\.com/v2/{os.environ['DNSIMPLE_ACCOUNT_ID']}/zones\\?.*"
            ),
            json={
                "data": [
                    {
                        "id": DNSIMPLE_ZONE_ID,
                        "account_id": int(os.environ["DNSIMPLE_ACCOUNT_ID"]),
                        "name": TEST_DOMAIN,
                        "reverse": False,
                        "secondary": False,
                        "last_transferred_at": False,
                        "active": True,
                        "created_at": "2015-04-23T07:40:03Z",
                        "updated_at": "2015-04-23T07:40:03Z",
                    },
                ],
                "pagination": {
                    "current_page": 1,
                    "per_page": 30,
                    "total_entries": 1,
                    "total_pages": 1,
                },
            },
        )

    @staticmethod
    def _stub_records_response(record_type: str):
        assert record_type in (None, "A", "AAAA")
        content = TEST_IP4 if record_type == "A" else TEST_IP6

        data = []
        if record_type:
            data = [
                {
                    "id": DNSIMPLE_RECORD_ID,
                    "zone_id": TEST_DOMAIN,
                    "parent_id": None,
                    "name": "",
                    "content": content,
                    "ttl": 3600,
                    "priority": None,
                    "type": record_type,
                    "regions": ["global"],
                    "system_record": False,
                    "created_at": "2016-03-22T10:20:53Z",
                    "updated_at": "2016-10-05T09:26:38Z",
                },
            ]

        return responses.add(
            method="GET",
            url=re.compile(
                f"https://api\\.dnsimple\\.com/v2/{os.environ['DNSIMPLE_ACCOUNT_ID']}/zones/{DNSIMPLE_ZONE_ID}/records.*"
            ),
            json={
                "data": data,
                "pagination": {
                    "current_page": 1,
                    "per_page": 30,
                    "total_entries": 1,
                    "total_pages": 1,
                },
            },
        )

    @staticmethod
    def _stub_record_update(method: str, content: str):
        assert method in ("PATCH", "POST")

        status_code = 201 if method == "POST" else 200

        url = f"https://api.dnsimple.com/v2/{os.environ['DNSIMPLE_ACCOUNT_ID']}/zones/{DNSIMPLE_ZONE_ID}/records"
        if method == "PATCH":
            url += f"/{DNSIMPLE_RECORD_ID}"

        return responses.add(
            method=method,
            url=url,
            json={
                "data": {
                    "id": DNSIMPLE_RECORD_ID,
                    "zone_id": TEST_DOMAIN,
                    "parent_id": None,
                    "name": "",
                    "content": content,
                    "ttl": 3600,
                    "priority": None,
                    "type": "A",
                    "regions": ["global"],
                    "system_record": False,
                    "created_at": "2016-10-05T09:51:35Z",
                    "updated_at": "2016-10-05T09:51:35Z",
                }
            },
            status=status_code,
        )

    @responses.activate
    def test_bad_auth(self):
        response = app.test_client().get(
            "/",
            query_string=IP4_DATA,
        )

        self.assertEqual(response.status_code, 401)

    @responses.activate
    def test_no_change(self):
        self._stub_zone_response()
        self._stub_records_response("A")

        response = app.test_client().get(
            "/",
            query_string=IP4_DATA,
            headers=AUTH_HEADER,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, f"nochg {TEST_IP4}")

    @responses.activate
    def test_change(self):
        self._stub_zone_response()
        self._stub_records_response("A")

        new_ip = "127.0.0.2"
        assert new_ip != TEST_IP4

        api_patch = self._stub_record_update("PATCH", new_ip)

        response = app.test_client().get(
            "/",
            query_string={**IP4_DATA, **{"myip": new_ip}},
            headers=AUTH_HEADER,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, f"good {new_ip}")
        patch_payload = api_patch.calls[0].response.json()
        self.assertEqual(patch_payload["data"]["type"], "A")
        self.assertEqual(patch_payload["data"]["content"], new_ip)

    @responses.activate
    def test_new_record(self):
        self._stub_zone_response()
        self._stub_records_response(None)

        api_post = self._stub_record_update("POST", TEST_IP4)

        response = app.test_client().get(
            "/",
            query_string=IP4_DATA,
            headers=AUTH_HEADER,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, f"good {TEST_IP4}")
        post_payload = api_post.calls[0].response.json()
        self.assertEqual(post_payload["data"]["type"], "A")
        self.assertEqual(post_payload["data"]["content"], TEST_IP4)

    def test_new_record_ipv6(self):
        """TODO"""

    def test_delete_extra_records(self):
        """TODO test deleting extra records if more than 1 already exist"""

    def test_zone_dns_lookup_errors(self):
        """TODO test error handling if SOA queries fail"""
