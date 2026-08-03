def test_rag_search_finds_semantically_relevant_events(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)

    response = client.get("/rag/search", params={"q": "failed login attempt by j.mehta"}, headers=analyst_headers)
    assert response.status_code == 200
    body = response.json()

    assert body["query"] == "failed login attempt by j.mehta"
    assert len(body["results"]) > 0
    assert any("j.mehta" in r["text"] for r in body["results"])


def test_rag_search_filters_by_content_type(client, analyst_headers):
    client.post("/simulate/phishing_ransomware", headers=analyst_headers)
    client.post("/correlate", headers=analyst_headers)

    response = client.get("/rag/search", params={"q": "ransomware", "content_type": "incident"}, headers=analyst_headers)
    body = response.json()

    assert len(body["results"]) > 0
    assert all(r["content_type"] == "incident" for r in body["results"])


def test_rag_search_requires_authentication(client):
    response = client.get("/rag/search", params={"q": "anything"})
    assert response.status_code == 401


def test_rag_search_rejects_empty_query(client, analyst_headers):
    response = client.get("/rag/search", params={"q": ""}, headers=analyst_headers)
    assert response.status_code == 422
