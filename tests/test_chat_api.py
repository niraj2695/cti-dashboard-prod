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

    context = chat.load_dashboard_context("CVE-2026-1234")

    assert context["generated"] == "now"
    assert context["feeds"]["kev"]["status"] == "ok"
    assert context["records"][0]["cve"] == "CVE-2026-1234"


def test_request_answer_uses_managed_identity_and_deployment(monkeypatch):
    azure_module = types.ModuleType("azure")
    identity_module = types.ModuleType("azure.identity")

    class Credential:
        def get_token(self, scope):
            assert scope == "https://cognitiveservices.azure.com/.default"
            return types.SimpleNamespace(token="managed-identity-token")

    identity_module.ManagedIdentityCredential = Credential
    azure_module.identity = identity_module
    monkeypatch.setitem(sys.modules, "azure", azure_module)
    monkeypatch.setitem(sys.modules, "azure.identity", identity_module)
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com/")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "cti-chat")
    captured = {}

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"content": "Grounded answer."}}]}

    def fake_post(url, **kwargs):
        captured.update(url=url, **kwargs)
        return Response()

    monkeypatch.setattr(chat.requests, "post", fake_post)
    answer = chat.request_answer("What happened?", {"records": []})

    assert answer == "Grounded answer."
    assert captured["url"] == "https://example.openai.azure.com/openai/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer managed-identity-token"
    assert captured["json"]["model"] == "cti-chat"


def test_missing_dashboard_data_is_a_service_error(tmp_path, monkeypatch):
    monkeypatch.setattr(chat, "DATA_DIR", tmp_path)
    with pytest.raises(chat.APIError) as error:
        chat.load_dashboard_context("question")
    assert error.value.status == 503
