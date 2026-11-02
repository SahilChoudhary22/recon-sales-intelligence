from ingest.extract import _san, slim


def cert(data):
    return {"extensions": [{"name": "subjectAltName", "data": data}]}


def test_san_strips_one_length_token():
    raw = "0?\\x82\\x10*.messinaline.it\\x82\\r*.htri-tn.com\\x82\\x0f*.imterminal.it\\x82\\x0bimperva.com"
    assert _san(cert(raw)) == ["*.htri-tn.com", "*.imterminal.it", "*.messinaline.it", "imperva.com"]


def test_san_printable_length_byte_not_glued_on():
    # 0x72 == "r" is a valid length byte; it must not become "rgabonactu.com"
    assert _san(cert("0\\x1a\\x82rgabonactu.com\\x82\\x11www.gabonactu.com")) == ["gabonactu.com", "www.gabonactu.com"]


def test_slim_handles_minimal_record():
    row = slim({"ip_str": "1.2.3.4", "port": 443, "_shodan": {"module": "https"}})
    assert row["ip"] == "1.2.3.4" and row["vulns"] == [] and row["cert_san"] == []
