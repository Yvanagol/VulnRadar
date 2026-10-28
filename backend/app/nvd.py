from datetime import datetime, timedelta, timezone
import re
from typing import Any
from urllib.parse import urlparse


NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SEVERITY_ORDER = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def build_nvd_params(
    query: str, days: int, start_index: int, results_per_page: int
) -> dict[str, str | int]:
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)
    params: dict[str, str | int] = {
        "pubStartDate": start_date.isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        ),
        "pubEndDate": end_date.isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        ),
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }

    normalized_query = query.strip()
    exact_id = bool(CVE_ID_PATTERN.fullmatch(normalized_query))
    if normalized_query:
        parameter = "cveId" if exact_id else "keywordSearch"
        params[parameter] = normalized_query.upper() if parameter == "cveId" else normalized_query
    if exact_id:
        params.pop("pubStartDate")
        params.pop("pubEndDate")
    return params


def normalize_response(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "totalResults": payload["totalResults"],
        "vulnerabilities": [
            parse_cve(item["cve"]) for item in payload["vulnerabilities"]
        ],
    }


def parse_cve(cve: dict[str, Any]) -> dict[str, Any]:
    descriptions = cve.get("descriptions") or []
    description = next(
        (item.get("value", "") for item in descriptions if item.get("lang") == "pt"),
        None,
    )
    if description is None:
        description = next(
            (item.get("value", "") for item in descriptions if item.get("lang") == "en"),
            descriptions[0].get("value", "") if descriptions else "",
        )

    metrics = cve.get("metrics") or {}
    metric = next(
        (
            entries[0]
            for key in SEVERITY_ORDER
            if (entries := metrics.get(key))
            and isinstance(entries, list)
            and entries
            and entries[0].get("cvssData")
        ),
        {},
    )
    cvss = metric.get("cvssData") or {}
    score = cvss.get("baseScore")
    severity = str(cvss.get("baseSeverity") or metric.get("baseSeverity") or "").upper()
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        if score is None:
            severity = "NONE"
        elif score >= 9:
            severity = "CRITICAL"
        elif score >= 7:
            severity = "HIGH"
        elif score >= 4:
            severity = "MEDIUM"
        elif score > 0:
            severity = "LOW"
        else:
            severity = "NONE"

    cwes: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for item in weakness.get("description") or []:
            value = item.get("value", "")
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value)

    products: list[str] = []

    def collect_products(nodes: list[dict[str, Any]]) -> None:
        for node in nodes:
            for match in node.get("cpeMatch") or []:
                if match.get("vulnerable"):
                    parts = match.get("criteria", "").split(":")
                    if len(parts) > 4:
                        product = f"{parts[3].replace('_', ' ')} {parts[4].replace('_', ' ')}"
                        if product not in products:
                            products.append(product)
            collect_products(node.get("children") or [])

    for configuration in cve.get("configurations") or []:
        collect_products(configuration.get("nodes") or [])

    references = [
        item["url"]
        for item in cve.get("references") or []
        if isinstance(item.get("url"), str)
        and urlparse(item["url"]).scheme in {"http", "https"}
        and urlparse(item["url"]).netloc
    ]

    return {
        "id": cve.get("id", ""),
        "description": description,
        "published": cve.get("published", ""),
        "lastModified": cve.get("lastModified", ""),
        "score": score,
        "severity": severity,
        "vector": cvss.get("vectorString"),
        "cwes": cwes,
        "affectedProducts": products[:4],
        "references": references,
    }
