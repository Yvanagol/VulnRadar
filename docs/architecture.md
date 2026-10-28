# Arquitetura inicial

## Fluxo da pesquisa

1. A interface React envia os filtros a `GET /api/cves`.
2. Em desenvolvimento, o proxy Vite encaminha a requisição ao FastAPI; no Compose, o Nginx faz o proxy.
3. O FastAPI valida período, tamanho do termo e limites de paginação, consulta o cache em memória e chama a NVD 2.0 com `httpx`.
4. A resposta é normalizada sem substituir a severidade informada pela NVD. A fonte e o instante da consulta acompanham os resultados.

## Escopo de dados

A API não persiste dados de negócio nesta fase. O cache é temporário e por processo. O serviço PostgreSQL já está definido no Docker Compose para a fase de histórico, ativos e tratamento de vulnerabilidades; nenhuma senha ou chave real deve ser armazenada no repositório.

## Endpoints iniciais

- `GET /health`: verificação de disponibilidade.
- `GET /api/cves`: consulta paginada da NVD.
- `GET /docs` e `GET /openapi.json`: documentação gerada pelo FastAPI.
