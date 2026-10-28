# Relatório de validação em runtime

**Data:** 2026-10-28  
**Projeto:** VulnRadar  
**Ambiente:** Windows, Node.js 24.22.0, Docker Engine 29.5.2, navegador integrado do VS Code (Chromium)

## Resumo

| Etapa | Resultado | Evidência |
|---|---|---|
| Inicialização | PASS | `docker compose --env-file .env.example up -d`; três serviços iniciados |
| Infraestrutura | PASS | PostgreSQL saudável; backend saudável; frontend ativo |
| API / testes | PASS | 10 testes de backend; `unittest` terminou com código 0 |
| Front-end | PASS | `npm run build` e `npm run lint` concluídos com código 0 |
| Compose | PASS | `docker compose --env-file .env.example config --quiet` |
| NVD real | PASS | CVE-2014-0160 retornou HTTP 200; pesquisa `Apache` retornou HTTP 200 |
| Navegador | PASS | Pesquisa, detalhes, referências, filtro, período, paginação, estados vazio/erro e recuperação |
| Responsividade | PASS | Viewport 390 px, sem rolagem horizontal |
| Swagger | PASS | `/docs` carregou pela rota publicada do frontend |

**Resultado geral:** PASS

## Testes de backend

Executado:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s backend\tests -v
```

Resultado: 10 testes aprovados, 0 falhas. Cobertura funcional: parâmetros NVD para CVE exato e palavra-chave, severidade informada pela NVD, referências HTTP/HTTPS, validação, rotas desconhecidas, paginação, cache, erros de conexão e limites da NVD.

## Testes no navegador

- Pesquisar `CVE-2014-0160`, conferir resultado e abrir a janela de detalhes com CVSS e referências oficiais.
- Pesquisar `Apache`: 366 registros reportados, 12 resultados na página.
- Avançar para a página seguinte e confirmar resultados diferentes.
- Filtrar por severidade alta e confirmar que os resultados exibidos são `HIGH`.
- Alterar o período para 7 e 90 dias; ambas as chamadas retornaram HTTP 200.
- Pesquisar termo sem correspondências e verificar o estado vazio.
- Pesquisar termo curto e verificar a mensagem de validação (HTTP 422); realizar nova busca válida e confirmar recuperação.
- Abrir `/docs` pelo Nginx do frontend.
- Em viewport móvel de 390 px, confirmar que a página não excede a largura disponível.

## Serviços ativos

O Compose foi deixado executando para que a aplicação permaneça disponível:

- Interface e Swagger: `http://localhost:8081` e `http://localhost:8081/docs`
- API e health check: `http://localhost:8000` e `http://localhost:8000/health`
- PostgreSQL local: porta `5432`

Use `docker compose down` na raiz do projeto para parar os serviços sem remover os dados persistidos.
