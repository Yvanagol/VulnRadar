# VulnRadar

Plataforma web para consultar CVEs na API oficial NVD 2.0. Esta primeira fase entrega pesquisa por identificador ou palavra-chave, severidade/CVSS, produtos afetados, referências oficiais, paginação, cache temporário e tratamento de erros. As consultas à NVD são feitas pelo back-end; nenhuma chave é enviada ao navegador.

## Requisitos

- Python 3.10+
- Node.js 20.19+ ou 22.12+
- Docker Desktop com Docker Compose (opcional)

## Executar no Windows

No PowerShell, na pasta do projeto:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
```

Inicie a API em um terminal:

```powershell
uvicorn app.main:app --reload --app-dir backend
```

Em outro terminal, inicie a interface:

```powershell
cd frontend
npm ci
npm run dev
```

Abra o endereço mostrado pelo Vite (normalmente `http://localhost:5173`). O proxy do Vite encaminha `/api` à API em `http://127.0.0.1:8000`. A documentação interativa da API fica em `http://127.0.0.1:8000/docs`; OpenAPI em `/openapi.json`.

Para configurar uma chave NVD, defina `NVD_API_KEY` no ambiente antes de iniciar o servidor. A chave é opcional para uso básico e permanece somente no back-end:

```powershell
$env:NVD_API_KEY = "sua-chave"
uvicorn app.main:app --reload --app-dir backend
```

## Executar com Docker Compose

Na raiz do projeto, copie o exemplo de ambiente e altere a senha local do PostgreSQL:

```powershell
Copy-Item .env.example .env
notepad .env
docker compose up --build
```

A interface fica em `http://localhost:8081`, a API em `http://localhost:8000` e o Swagger em `http://localhost:8081/docs`. O PostgreSQL é iniciado e persistido em volume para as próximas fases; a Fase 1 não grava dados de negócio no banco.

Para encerrar os serviços sem apagar o volume do PostgreSQL:

```powershell
docker compose down
```

## Pesquisa e dados

- `GET /api/cves?query=Apache&days=30&startIndex=0&resultsPerPage=12`
- Identificadores CVE exatos usam o parâmetro `cveId` da NVD; outros termos usam `keywordSearch`.
- Consultas por fabricante/produto são textuais nesta fase; a resolução estruturada de CPE fica para uma etapa posterior.
- Para resultados por palavra-chave, informe pelo menos três caracteres. O período aceita 7, 30 ou 90 dias; páginas têm no máximo 200 resultados.
- O cache em memória dura cinco minutos e é local ao processo da API. Respostas da NVD com limite de requisições e falhas de conexão são comunicadas ao front-end.
- Gravidade e pontuação são preservadas conforme as métricas CVSS fornecidas pela NVD; registros sem classificação permanecem como `NONE`.
- Cada resultado inclui a fonte, data/hora da consulta, data de publicação/alteração e referências recebidas da NVD. Os links de referência aceitam somente HTTP/HTTPS.

## Estrutura

```text
backend/
  app/                 API FastAPI e integração NVD
  tests/               testes automatizados da API
  Dockerfile
frontend/
  src/                 interface React + Vite
  Dockerfile
  nginx.conf
docs/                  notas técnicas
docker-compose.yml
.env.example
```

## Testes e build

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s backend\tests -v
cd frontend
npm run build
npm run lint
```

## Escopo incremental

Esta entrega cobre a pesquisa inicial (Fases 1 e parte da 2). Persistência de consultas/ativos, PostgreSQL no fluxo da aplicação, CISA KEV, gráficos, contas, autenticação e auditoria continuam planejados para as fases seguintes e não são simulados nesta versão.
