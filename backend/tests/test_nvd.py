import unittest

import httpx

from backend.app.cache import ResponseCache
from backend.app.main import app
from backend.app.nvd import build_nvd_params, parse_cve


class NvdParsingTests(unittest.TestCase):
    def test_exact_cve_id_uses_nvd_identifier_parameter_without_date_filter(self):
        params = build_nvd_params("cve-2026-12345", 30, 24, 12)

        self.assertEqual(params["cveId"], "CVE-2026-12345")
        self.assertNotIn("keywordSearch", params)
        self.assertNotIn("pubStartDate", params)
        self.assertNotIn("pubEndDate", params)
        self.assertNotIn("sortBy", params)
        self.assertNotIn("sortOrder", params)
        self.assertEqual(params["startIndex"], 24)

    def test_keyword_uses_nvd_keyword_search(self):
        params = build_nvd_params("Apache HTTP Server", 7, 0, 12)

        self.assertEqual(params["keywordSearch"], "Apache HTTP Server")
        self.assertNotIn("cveId", params)
        self.assertIn("pubStartDate", params)
        self.assertNotIn("sortBy", params)
        self.assertNotIn("sortOrder", params)

    def test_preserves_severity_reported_by_nvd_and_includes_references(self):
        record = parse_cve(
            {
                "id": "CVE-2026-12345",
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 8.0,
                                "baseSeverity": "MEDIUM",
                                "vectorString": "CVSS:3.1/example",
                            }
                        }
                    ]
                },
                "references": [
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"}
                ],
            }
        )

        self.assertEqual(record["severity"], "MEDIUM")
        self.assertEqual(record["score"], 8.0)
        self.assertEqual(
            record["references"],
            ["https://nvd.nist.gov/vuln/detail/CVE-2026-12345"],
        )

    def test_discards_non_http_reference_urls(self):
        record = parse_cve(
            {
                "id": "CVE-2026-12345",
                "references": [
                    {"url": "javascript:alert(1)"},
                    {"url": "https://nvd.nist.gov/reference"},
                ],
            }
        )

        self.assertEqual(record["references"], ["https://nvd.nist.gov/reference"])


class NvdEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.upstream_response = httpx.Response(
            200,
            json={
                "totalResults": 1,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-12345",
                            "descriptions": [
                                {"lang": "en", "value": "Test vulnerability"}
                            ],
                            "published": "2026-10-01T00:00:00.000",
                            "lastModified": "2026-10-02T00:00:00.000",
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {
                                            "baseScore": 9.8,
                                            "baseSeverity": "CRITICAL",
                                            "vectorString": "CVSS:3.1/example",
                                        }
                                    }
                                ]
                            },
                            "weaknesses": [
                                {"description": [{"value": "CWE-79"}]}
                            ],
                            "configurations": [
                                {
                                    "nodes": [
                                        {
                                            "cpeMatch": [
                                                {
                                                    "criteria": "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
                                                    "vulnerable": True,
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                            "references": [{"url": "https://nvd.nist.gov/reference"}],
                        }
                    }
                ],
            },
        )
        self.calls = 0
        self.request_params = []
        self.request_error = None
        self.lifespan = app.router.lifespan_context(app)
        await self.lifespan.__aenter__()
        self.upstream = httpx.AsyncClient(
            transport=httpx.MockTransport(self.respond)
        )
        app.state.nvd_client = self.upstream
        app.state.response_cache = ResponseCache()
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        )

    async def asyncTearDown(self):
        await self.client.aclose()
        await self.upstream.aclose()
        await self.lifespan.__aexit__(None, None, None)

    def respond(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self.request_params.append(dict(request.url.params))
        if self.request_error:
            raise self.request_error
        return self.upstream_response

    async def test_search_returns_nvd_data_and_caches_response(self):
        first = await self.client.get("/api/cves?query=Apache&days=7")
        second = await self.client.get("/api/cves?query=Apache&days=7")

        self.assertEqual(first.status_code, 200)
        data = first.json()
        self.assertEqual(data["source"], "NIST National Vulnerability Database (NVD)")
        self.assertIn("updatedAt", data)
        self.assertEqual(data["totalResults"], 1)
        record = data["vulnerabilities"][0]
        self.assertEqual(record["id"], "CVE-2026-12345")
        self.assertEqual(record["severity"], "CRITICAL")
        self.assertEqual(record["cwes"], ["CWE-79"])
        self.assertEqual(record["affectedProducts"], ["example product"])
        self.assertEqual(record["references"], ["https://nvd.nist.gov/reference"])
        self.assertEqual(second.json(), data)
        self.assertEqual(self.calls, 1)
        self.assertEqual(self.request_params[0]["keywordSearch"], "Apache")
        self.assertEqual(self.request_params[0]["resultsPerPage"], "12")

    async def test_rejects_invalid_parameters(self):
        for url in (
            "/api/cves?days=8",
            "/api/cves?startIndex=-1",
            "/api/cves?resultsPerPage=201",
            "/api/cves?query=ab",
            f"/api/cves?query={'x' * 201}",
        ):
            with self.subTest(url=url):
                response = await self.client.get(url)
                self.assertEqual(response.status_code, 422)
                self.assertIn("error", response.json())

    async def test_unknown_api_route_returns_json_error(self):
        response = await self.client.get("/api/unknown")

        self.assertEqual(response.status_code, 404)
        self.assertIn("error", response.json())

    async def test_openapi_documents_search_endpoint(self):
        response = await self.client.get("/openapi.json")

        self.assertEqual(response.status_code, 200)
        self.assertIn("/api/cves", response.json()["paths"])

    async def test_maps_upstream_rate_limit_to_429(self):
        self.upstream_response = httpx.Response(
            429,
            request=httpx.Request("GET", "https://services.nvd.nist.gov"),
        )

        response = await self.client.get("/api/cves?query=rate-limit-case")

        self.assertEqual(response.status_code, 429)
        self.assertIn("NVD limitou", response.json()["error"])

    async def test_maps_network_error_to_502(self):
        self.request_error = httpx.ConnectError("connection refused")

        response = await self.client.get("/api/cves?query=network-error-case")

        self.assertEqual(response.status_code, 502)
        self.assertIn("conectar à NVD", response.json()["error"])
