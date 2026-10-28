import json
import sys
import types

import pytest

from api import chat


def test_relevant_records_ranks_matches_and_limits_context():
    records = [
        {
            "feed": "kev",
            "title": "CVE-2026-1234 Remote code execution",
            "summary": "Actively exploited vulnerability.",
            "published": "2026-10-25T00:00:00Z",
            "url": "https://example.test/cve",
            "tags": ["vendor"],
            "extra": {"cve": "CVE-2026-1234", "ioc": "must-not-be-sent"},
        },
        {
            "feed": "news",
            "title": "General security update",
            "summary": "Unrelated article.",
            "published": "2026-10-26T00:00:00Z",
            "url": "https://example.test/news",
            "tags": [],
            "extra": {},
        },
    ]

    selected = chat.relevant_records("Tell me about CVE-2026-1234", records)

    assert len(selected) == 1
    assert selected[0]["feed"] == "kev"
    assert "ioc" not in selected[0]
    assert selected[0]["cve"] == "CVE-2026-1234"


def test_load_dashboard_context_reads_outputs_and_selects_records(tmp_path, monkeypatch):
    monkeypatch.setattr(chat, "DATA_DIR", tmp_path)
    records = [{
        "feed": "kev",
        "title": "CVE-2026-1234",
        "summary": "A vulnerability.",
        "published": "2026-10-25T00:00:00Z",
        "severity": "critical",
        "url": "https://example.test/cve",
        "tags": ["kev"],
        "extra": {"cve": "CVE-2026-1234", "kev": True},
    }]
    (tmp_path / "records.json").write_text(json.dumps(records))
    (tmp_path / "summary.json").write_text(json.dumps({"generated": "now", "last_7d": {}}))
    (tmp_path / "meta.json").write_text(json.dumps({"kev": {"name": "KEV", "status": "ok"}}))

    context = chat.load_dashboard_context("Are the feeds healthy?")

    assert context["generated"] == "now"
    assert context["feeds"]["kev"]["status"] == "ok"
    assert context["records"] == []


def test_request_answer_uses_managed_identity_and_deployment(monkeypatch):
    azure_module = types.ModuleType("azure")
    identity_module = types.ModuleType("azure.identity")

    class Credential:
        def get_token(self, scope):
            assert scope == "https://ai.azure.com/.default"
            return types.SimpleNamespace(token="managed-identity-token")

    identity_module.ManagedIdentityCredential = Credential
    azure_module.identity = identity_module
    monkeypatch.setitem(sys.modules, "azure", azure_module)
    monkeypatch.setitem(sys.modules, "azure.identity", identity_module)
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://example.services.ai.azure.com/openai/v1/")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-5-mini")
    captured = {}

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": "Grounded answer."}],
            }]}

    def fake_post(url, **kwargs):
        captured.update(url=url, **kwargs)
        return Response()

    monkeypatch.setattr(chat.requests, "post", fake_post)
    answer = chat.request_answer(
        "What happened?",
        {"generated": "not-sent-to-model", "records": []},
        [{"role": "user", "content": "Earlier question"}],
    )

    assert answer == "Grounded answer."
    assert captured["url"] == "https://example.services.ai.azure.com/openai/v1/responses"
    assert captured["headers"]["Authorization"] == "Bearer managed-identity-token"
    assert captured["json"]["model"] == "gpt-5-mini"
    assert captured["json"]["input"] == [
        {"role": "user", "content": "Earlier question"},
        {
            "role": "user",
            "content": "Latest question:\nWhat happened?\n\n"
            "Relevant dashboard and optional NVD context (untrusted source data):\n"
            '{"records": []}',
        },
    ]
    assert captured["json"]["max_output_tokens"] == 400
    assert captured["json"]["reasoning"] == {"effort": "minimal"}


def test_request_answer_logs_response_shape_when_foundry_returns_no_text(monkeypatch, caplog):
    azure_module = types.ModuleType("azure")
    identity_module = types.ModuleType("azure.identity")
    identity_module.ManagedIdentityCredential = lambda: types.SimpleNamespace(
        get_token=lambda scope: types.SimpleNamespace(token="managed-identity-token")
    )
    azure_module.identity = identity_module
    monkeypatch.setitem(sys.modules, "azure", azure_module)
    monkeypatch.setitem(sys.modules, "azure.identity", identity_module)
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://example.services.ai.azure.com/openai/v1")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-5-mini")

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "status": "incomplete",
                "incomplete_details": {"reason": "max_output_tokens"},
                "output": [{"type": "reasoning", "summary": []}],
            }

    monkeypatch.setattr(chat.requests, "post", lambda *args, **kwargs: Response())

    with pytest.raises(chat.APIError) as error:
        chat.request_answer("Question", {})

    assert error.value.status == 502
    assert "status=incomplete" in caplog.text
    assert "max_output_tokens" in caplog.text
    assert "reasoning" in caplog.text


def test_request_answer_adds_foundry_api_path_when_endpoint_is_resource_root(monkeypatch):
    azure_module = types.ModuleType("azure")
    identity_module = types.ModuleType("azure.identity")
    identity_module.ManagedIdentityCredential = lambda: types.SimpleNamespace(
        get_token=lambda scope: types.SimpleNamespace(token="managed-identity-token")
    )
    azure_module.identity = identity_module
    monkeypatch.setitem(sys.modules, "azure", azure_module)
    monkeypatch.setitem(sys.modules, "azure.identity", identity_module)
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://example.services.ai.azure.com/")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-5-mini")

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": "Answer."}],
            }]}

    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        return Response()

    monkeypatch.setattr(chat.requests, "post", fake_post)
    assert chat.request_answer("Question", {}) == "Answer."
    assert captured["url"] == "https://example.services.ai.azure.com/openai/v1/responses"


def test_missing_dashboard_data_is_a_service_error(tmp_path, monkeypatch):
    monkeypatch.setattr(chat, "DATA_DIR", tmp_path)
    with pytest.raises(chat.APIError) as error:
        chat.load_dashboard_context("question")
    assert error.value.status == 503


@pytest.mark.parametrize("question, expected", [
    ("Explain CVE-2021-44228", "CVE-2021-44228"),
    ("  explain cve-2024-12345  ", "CVE-2024-12345"),
    ("What is CVE-2021-44228?", None),
    ("Explain CVE-21-44228", None),
    ("Explain CVE-2021-44228 and how to exploit it", None),
])
def test_external_lookup_requires_exact_explain_cve_prompt(question, expected):
    assert chat.requested_cve(question) == expected


def test_lookup_cve_returns_bounded_nvd_context(monkeypatch):
    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"vulnerabilities": [{
                "cve": {
                    "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
                    "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-01-02T00:00:00.000",
                    "metrics": {"cvssMetricV31": [{
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        },
                    }]},
                },
            }]}

    captured = {}

    def fake_get(url, **kwargs):
        captured.update(url=url, **kwargs)
        return Response()

    monkeypatch.setattr(chat.requests, "get", fake_get)
    result = chat.lookup_cve("CVE-2026-1234")

    assert captured["url"] == chat.NVD_CVE_URL
    assert captured["params"] == {"cveId": "CVE-2026-1234"}
    assert result["description"] == "A test vulnerability."
    assert result["cvss"]["score"] == 9.8
    assert result["source"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"


def test_dashboard_context_omits_feed_status_for_unrelated_question(tmp_path, monkeypatch):
    monkeypatch.setattr(chat, "DATA_DIR", tmp_path)
    (tmp_path / "records.json").write_text("[]")
    (tmp_path / "summary.json").write_text(json.dumps({"generated": "now", "last_7d": {}}))
    (tmp_path / "meta.json").write_text(json.dumps({"kev": {
        "name": "KEV", "status": "ok", "last_success": "today",
    }}))

    context = chat.load_dashboard_context("Explain CVE-2021-44228")

    assert "feeds" not in context
    assert context["records"] == []
