import json

from collectors import tridentstack
from collectors.base import Context


def test_tridentstack_request_limit_and_cursor_resume(tmp_path, monkeypatch):
    ctx = Context(tmp_path)
    calls = []

    class Response:
        def __init__(self, cursor):
            self.cursor = cursor

        def json(self):
            return {"results": [], "nextCursor": self.cursor}

    def fake_get(_ctx, _url, *, params, before_request):
        before_request()
        calls.append(params)
        page = len(calls)
        return Response(str(page) if page < 51 else None)

    monkeypatch.setattr(tridentstack, "get", fake_get)

    assert tridentstack.collect(ctx) == []
    assert len(calls) == tridentstack.REQUEST_LIMIT
    state_path = tmp_path / tridentstack.STATE_FILE
    state = json.loads(state_path.read_text())
    assert state["cursor"] == str(tridentstack.REQUEST_LIMIT)
    assert len(state["request_timestamps"]) == tridentstack.REQUEST_LIMIT

    assert tridentstack.collect(ctx) == []
    assert len(calls) == tridentstack.REQUEST_LIMIT

    state["request_timestamps"] = [0] * tridentstack.REQUEST_LIMIT
    state_path.write_text(json.dumps(state))
    assert tridentstack.collect(ctx) == []
    assert calls[-1]["nextCursor"] == str(tridentstack.REQUEST_LIMIT)
    assert json.loads(state_path.read_text())["cursor"] is None
