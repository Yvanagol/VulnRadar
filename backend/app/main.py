import hashlib
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Any

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .cache import ResponseCache
from .nvd import CVE_ID_PATTERN, NVD_ENDPOINT, build_nvd_params, normalize_response


logger = logging.getLogger("vulnradar.nvd")


@asynccontextmanager
async def lifespan(app: FastAPI):
    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    async with httpx.AsyncClient(timeout=20, headers=headers) as client:
        app.state.nvd_client = client
        app.state.response_cache = ResponseCache(
            ttl_seconds=int(os.getenv("CACHE_TTL_SECONDS", "300"))
        )
        yield


app = FastAPI(
    title="VulnRadar API",
    description="Pesquisa CVEs na API oficial NVD 2.0.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(
    _request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    _request: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"error": "Parâmetros inválidos.", "details": exc.errors()},
    )


@app.get("/health", tags=["health"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/cves", tags=["vulnerabilities"])
async def search_cves(
    request: Request,
    query: Annotated[str, Query(max_length=200)] = "",
    days: Annotated[int, Query(ge=1, le=90)] = 30,
    start_index: Annotated[int, Query(alias="startIndex", ge=0, le=2_000_000)] = 0,
    results_per_page: Annotated[
        int, Query(alias="resultsPerPage", ge=1, le=200)
    ] = 12,
) -> dict[str, Any]:
    if days not in {7, 30, 90}:
        raise HTTPException(status_code=422, detail="O período deve ser 7, 30 ou 90 dias.")
    if query and not CVE_ID_PATTERN.fullmatch(query.strip()) and len(query.strip()) < 3:
        raise HTTPException(
            status_code=422,
            detail="Use pelo menos 3 caracteres para pesquisar por palavra-chave.",
        )

    cache_key = hashlib.sha256(
        json.dumps(
            [query.casefold(), days, start_index, results_per_page],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    cache: ResponseCache = request.app.state.response_cache
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    params = build_nvd_params(query, days, start_index, results_per_page)
    client: httpx.AsyncClient = request.app.state.nvd_client
    try:
        response = await client.get(NVD_ENDPOINT, params=params)
    except httpx.RequestError as exc:
        logger.exception("Falha ao consultar a API da NVD.")
        raise HTTPException(
            status_code=502,
            detail="Não foi possível conectar à NVD. Tente novamente em instantes.",
        ) from exc

    if response.status_code in {403, 429}:
        raise HTTPException(
            status_code=429,
            detail="A NVD limitou temporariamente as consultas. Aguarde e tente novamente.",
        )
    if not response.is_success:
        logger.error("A NVD respondeu com HTTP %s.", response.status_code)
        raise HTTPException(
            status_code=502,
            detail=f"A consulta à NVD falhou (HTTP {response.status_code}).",
        )

    try:
        result = normalize_response(response.json())
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        logger.exception("A NVD retornou uma resposta JSON inválida.")
        raise HTTPException(
            status_code=502,
            detail="A NVD retornou uma resposta inválida. Tente novamente em instantes.",
        ) from exc

    result["source"] = "NIST National Vulnerability Database (NVD)"
    result["updatedAt"] = datetime.now(timezone.utc).isoformat()
    cache.set(cache_key, result)
    return result
