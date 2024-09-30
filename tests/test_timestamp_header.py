import requests


def test_timestamp_header():
    req = requests.Request("GET", "https://httpbin.org/")
    s = requests.Session()
    prep = s.prepare_request(req)

    assert "X-Cosine-Client-Timestamp" in prep.headers
