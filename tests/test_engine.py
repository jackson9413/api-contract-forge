"""Smoke tests for API Contract Forge."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import analyze, parse_contract, render_markdown, to_yaml  # noqa: E402
from samples import SAMPLES, SAMPLE_BY_ID  # noqa: E402

import app as flask_app  # noqa: E402


def ids_of(report):
    return {f["id"] for f in report["findings"]}


class ParseTests(unittest.TestCase):
    def test_brief_parses_endpoints_fields_statuses(self):
        model = parse_contract(SAMPLE_BY_ID["orders-brief"]["content"], "brief")
        self.assertEqual(len(model["endpoints"]), 5)
        paths = {(e["method"], e["path"]) for e in model["endpoints"]}
        self.assertIn(("POST", "/v1/orders"), paths)
        self.assertIn(("GET", "/v1/orders/{order_id}"), paths)
        post = next(e for e in model["endpoints"] if e["method"] == "POST")
        names = [f["name"] for f in post["body_fields"]]
        self.assertIn("customer_id", names)
        self.assertTrue(any(f["required"] for f in post["body_fields"]))
        self.assertIn(201, post["statuses"])
        get_list = next(e for e in model["endpoints"]
                        if e["method"] == "GET" and e["path"] == "/v1/orders")
        limit = next(p for p in get_list["query_fields"] if p["name"] == "limit")
        self.assertEqual(limit["default"], 25)
        self.assertEqual(limit["max"], 100)

    def test_prose_verbs_are_not_endpoints(self):
        model = parse_contract(SAMPLE_BY_ID["payments-messy"]["content"], "brief")
        self.assertEqual(len(model["endpoints"]), 5)
        for ep in model["endpoints"]:
            self.assertTrue(ep["path"].startswith("/"), ep["path"])

    def test_messy_brief_extracts_bare_fields(self):
        model = parse_contract(SAMPLE_BY_ID["payments-messy"]["content"], "brief")
        post = next(e for e in model["endpoints"] if e["method"] == "POST")
        names = [f["name"] for f in post["body_fields"]]
        self.assertIn("card_number", names)
        resp = next(e for e in model["endpoints"] if e["method"] == "GET"
                    and e["path"] == "/payments")
        self.assertIn("data", [f["name"] for f in resp["response_fields"]])

    def test_openapi_parsing(self):
        model = parse_contract(SAMPLE_BY_ID["payments-openapi"]["content"], "openapi")
        self.assertEqual(model["mode"], "openapi")
        self.assertEqual(model["title"], "Payments API")
        ops = {(e["method"], e["path"]) for e in model["endpoints"]}
        self.assertIn(("GET", "/charges"), ops)
        self.assertIn(("PATCH", "/charges/{chargeId}"), ops)
        self.assertTrue(model["auth_declared"])
        self.assertTrue(any(e["operation_id"] == "listCharges" for e in model["endpoints"]))

    def test_auto_mode_detects_openapi(self):
        model = parse_contract(SAMPLE_BY_ID["payments-openapi"]["content"], "auto")
        self.assertEqual(model["mode"], "openapi")

    def test_invalid_json_raises(self):
        with self.assertRaises(ValueError):
            parse_contract("{not json", "openapi")


class RuleTests(unittest.TestCase):
    def test_strong_contract_scores_production_ready(self):
        report = analyze(parse_contract(SAMPLE_BY_ID["orders-brief"]["content"], "brief"), "rest")
        self.assertGreaterEqual(report["score"], 85)
        self.assertEqual(report["verdict"], "prod_ready")
        self.assertEqual(report["counts"]["high"], 0)

    def test_messy_contract_fires_core_rules(self):
        report = analyze(parse_contract(SAMPLE_BY_ID["payments-messy"]["content"], "brief"), "rest")
        found = ids_of(report)
        for rule in ("no_authentication_declared", "no_error_responses",
                     "list_without_pagination", "no_versioning",
                     "sensitive_field_exposed", "create_without_idempotency_key"):
            self.assertIn(rule, found)
        self.assertLess(report["score"], 60)
        self.assertEqual(report["verdict"], "tight_but_usable")

    def test_openapi_contract_flags_gaps(self):
        report = analyze(parse_contract(SAMPLE_BY_ID["payments-openapi"]["content"], "openapi"), "rest")
        found = ids_of(report)
        for rule in ("no_auth_failure_codes", "undeclared_path_param",
                     "unbounded_page_size", "insecure_server_url",
                     "patch_without_precondition", "missing_operation_ids"):
            self.assertIn(rule, found)

    def test_webhook_contract_flags_signature_and_event_id(self):
        report = analyze(parse_contract(SAMPLE_BY_ID["events-webhook"]["content"], "brief"), "rest")
        found = ids_of(report)
        self.assertIn("webhook_unsigned", found)
        self.assertIn("webhook_without_event_id", found)

    def test_profile_weights_change_the_score(self):
        model = parse_contract(SAMPLE_BY_ID["payments-messy"]["content"], "brief")
        rest = analyze(model, "rest")
        public = analyze(model, "public")
        self.assertNotEqual(rest["score"], public["score"])
        self.assertEqual(public["profile"], "public")

    def test_axes_and_caps_present(self):
        report = analyze(parse_contract(SAMPLE_BY_ID["payments-messy"]["content"], "brief"), "rest")
        self.assertEqual(len(report["axes"]), 6)
        paging = next(a for a in report["axes"] if a["key"] == "pagination")
        self.assertTrue(paging["cap"])
        self.assertLessEqual(paging["score"], 35)

    def test_export_helpers(self):
        report = analyze(parse_contract(SAMPLE_BY_ID["orders-brief"]["content"], "brief"), "rest")
        md = render_markdown(report)
        self.assertIn("# API contract review", md)
        self.assertIn("## Findings", md)
        yaml = to_yaml(report["openapi"])
        self.assertIn("openapi: 3.0.3", yaml)
        self.assertIn("paths:", yaml)
        json.dumps(report)


class HttpTests(unittest.TestCase):
    def setUp(self):
        flask_app.app.config["TESTING"] = True
        self.client = flask_app.app.test_client()

    def test_health(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])

    def test_index_renders(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"API Contract Forge", r.data)

    def test_samples_endpoint(self):
        r = self.client.get("/api/samples")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.get_json()["samples"]), len(SAMPLES))

    def test_analyze_brief(self):
        r = self.client.post("/api/analyze", json={
            "input": SAMPLE_BY_ID["orders-brief"]["content"], "mode": "brief", "profile": "rest"})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertGreaterEqual(data["score"], 85)
        self.assertTrue(data["session_id"])
        self.assertEqual(len(data["axes"]), 6)

    def test_analyze_openapi(self):
        r = self.client.post("/api/analyze", json={
            "input": SAMPLE_BY_ID["payments-openapi"]["content"], "mode": "openapi"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["mode"], "openapi")

    def test_analyze_rejects_empty(self):
        r = self.client.post("/api/analyze", json={"input": "   "})
        self.assertEqual(r.status_code, 400)

    def test_analyze_rejects_unparseable_openapi(self):
        r = self.client.post("/api/analyze", json={"input": "{oops", "mode": "openapi"})
        self.assertEqual(r.status_code, 400)

    def test_analyze_rejects_text_without_endpoints(self):
        r = self.client.post("/api/analyze", json={"input": "hello there", "mode": "brief"})
        self.assertEqual(r.status_code, 400)

    def test_session_lifecycle_and_exports(self):
        r = self.client.post("/api/analyze", json={
            "input": SAMPLE_BY_ID["orders-brief"]["content"], "mode": "brief"})
        sid = r.get_json()["session_id"]
        r2 = self.client.get("/api/sessions/%d" % sid)
        self.assertEqual(r2.status_code, 200)
        r3 = self.client.patch("/api/sessions/%d" % sid, json={"notes": "looks good", "rating": 4})
        self.assertEqual(r3.status_code, 200)
        self.assertEqual(r3.get_json()["notes"], "looks good")
        self.assertEqual(r3.get_json()["rating"], 4)
        md = self.client.get("/api/export/%d?fmt=md" % sid)
        self.assertEqual(md.status_code, 200)
        self.assertIn(b"# API contract review", md.data)
        js = self.client.get("/api/export/%d?fmt=json" % sid)
        self.assertEqual(js.status_code, 200)
        self.assertIn("axes", js.get_json())
        yml = self.client.get("/api/export/%d?fmt=yaml" % sid)
        self.assertEqual(yml.status_code, 200)
        self.assertIn(b"openapi: 3.0.3", yml.data)

    def test_session_list(self):
        r = self.client.get("/api/sessions")
        self.assertEqual(r.status_code, 200)
        self.assertIn("sessions", r.get_json())


if __name__ == "__main__":
    unittest.main(verbosity=2)
