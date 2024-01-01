import base64
import random
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

import app

flask_app = app.app


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
    def _stub_records_response(
        record_type: str,
        record_count: int = 1,
    ):
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
            ] * record_count

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
                    "total_entries": record_count,
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

        default_response_data = {
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

        def response_handler(request):
            return (
                status_code,
                {},
                json.dumps(
                    {
                        "data": {
                            **default_response_data,
                            **json.loads(request.body),
                        }
                    }
                ),
            )

        responses.add_callback(
            method=method,
            url=url,
            callback=response_handler,
        )

    @staticmethod
    def _stub_record_delete():
        return responses.add(
            method="DELETE",
            url=re.compile(
                "https://api.dnsimple.com"
                f"/v2/{os.environ['DNSIMPLE_ACCOUNT_ID']}"
                f"/zones/{DNSIMPLE_ZONE_ID}"
                "/records/[0-9]+"
            ),
            status=204,
        )

    @responses.activate
    def test_bad_auth(self):
        response = flask_app.test_client().get(
            "/",
            query_string=IP4_DATA,
        )

        self.assertEqual(401, response.status_code)

    @responses.activate
    def test_no_change(self):
        self._stub_zone_response()
        self._stub_records_response("A")

        response = flask_app.test_client().get(
            "/",
            query_string=IP4_DATA,
            headers=AUTH_HEADER,
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual(f"nochg {TEST_IP4}", response.text)

    @responses.activate(assert_all_requests_are_fired=True)
    def test_change(
        self,
        existing_record_count: int = 1,
    ):
        self._stub_zone_response()
        self._stub_records_response("A", record_count=existing_record_count)

        new_ip = "127.0.0.2"
        assert new_ip != TEST_IP4

        self._stub_record_update("PATCH", new_ip)

        response = flask_app.test_client().get(
            "/",
            query_string={**IP4_DATA, **{"myip": new_ip}},
            headers=AUTH_HEADER,
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual(f"good {new_ip}", response.text)

        update_call = [
            call for call in responses.calls if call.request.method == "PATCH"
        ]

        self.assertEqual(1, len(update_call))
        request_body = json.loads(update_call[0].request.body.decode("utf8"))
        self.assertEqual(new_ip, request_body["content"])

        return request_body

    def test_change_with_ttl_set(self):
        # some artificially small values
        ttl = random.randint(1, 59)
        # double check it's actually changed
        assert ttl != app.DEFAULT_RECORD_TTL
        os.environ["DNS_TTL"] = str(ttl)

        import importlib

        # A little hacky, reload the app with new environment
        importlib.reload(app)

        request_body = self.test_change()

        # Put the environment back
        del os.environ["DNS_TTL"]
        importlib.reload(app)

        self.assertEqual(ttl, request_body["ttl"])

    def test_delete_extra_records(self):
        self._stub_record_delete()

        # assert_all_requests_are_fired=True on test_change will cause a failure if
        # the delete stub wasn't called
        self.test_change(
            existing_record_count=2,
        )

    @responses.activate
    def test_new_record(
        self, record_type: str = "A", param_name: str = "myip", content: str = TEST_IP4
    ):
        self._stub_zone_response()
        self._stub_records_response(None)

        self._stub_record_update("POST", content)

        response = flask_app.test_client().get(
            "/",
            query_string={
                "hostname": TEST_DOMAIN,
                param_name: content,
            },
            headers=AUTH_HEADER,
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual(f"good {content}", response.text)
        update_call = [
            call for call in responses.calls if call.request.method == "POST"
        ]
        self.assertEqual(1, len(update_call))
        request_body = json.loads(update_call[0].request.body.decode("utf8"))

        self.assertEqual(record_type, request_body["type"])
        self.assertEqual(content, request_body["content"])

    def test_new_record_ipv6(self):
        self.test_new_record(
            record_type="AAAA",
            param_name="myipv6",
            content=TEST_IP6,
        )

    def test_zone_dns_lookup_errors(self):
        """TODO test error handling if SOA queries fail"""
