"""👎 in one click: a reason is enough, the correction stays optional; the reasons are counted."""
import pytest

from heliosdbg import feedback


def _recent():
    return {"a1": {"messages": [{"role": "system", "content": "x"}, {"role": "user", "content": "q"}], "answer": "16 switches",
                   "model": "helios", "subject": "the rack (chat)"}}


def test_a_reason_alone_is_enough(tmp_path):
    r = feedback.record(tmp_path, {"answer_id": "a1", "rating": "down", "reasons": ["wrong_count", "bogus"]}, _recent())
    assert r["reasons"] == ["wrong_count"] and r["correction"] == ""
    assert feedback.stats(tmp_path)["reasons"] == {"wrong_count": 1}


def test_a_thumbs_down_says_what_was_wrong(tmp_path):
    with pytest.raises(feedback.FeedbackError):
        feedback.record(tmp_path, {"answer_id": "a1", "rating": "down"}, _recent())
    assert feedback.record(tmp_path, {"answer_id": "a1", "rating": "up"}, _recent())["reasons"] == []


def test_ui_reasons_match():
    from pathlib import Path
    html = (Path(__file__).resolve().parent.parent / "ui" / "static" / "index.html").read_text()
    for k in feedback.REASONS:
        assert f'["{k}",' in html
