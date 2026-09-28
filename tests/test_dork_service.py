from collections import Counter
from urllib.parse import parse_qs, urlparse

from services import dork_service


def _all_queries(domain="example.com"):
    return [q for group in dork_service.dork_categories_for_domain(domain) for q in group["queries"]]


def test_every_query_is_scoped_to_the_target():
    for item in _all_queries():
        assert "example.com" in item["query"], item["label"]


def test_no_template_placeholder_is_left_unfilled():
    for item in _all_queries():
        assert "{domain}" not in item["query"], item["label"]


def test_labels_are_unique_within_a_category():
    for group in dork_service.dork_categories_for_domain("example.com"):
        counts = Counter(q["label"] for q in group["queries"])
        assert all(n == 1 for n in counts.values()), group["category"]


def test_google_url_round_trips_the_query():
    for item in _all_queries():
        parsed = urlparse(item["url"])
        assert parsed.netloc == "www.google.com"
        assert parse_qs(parsed.query)["q"] == [item["query"]]


def test_total_count_matches_the_rendered_catalog():
    assert dork_service.total_dork_count() == len(_all_queries())
    assert dork_service.total_dork_count() >= 60
