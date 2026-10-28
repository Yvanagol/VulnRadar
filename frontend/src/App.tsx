import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import {
  fetchCves,
  type CveRecord,
  type Severity,
} from './lib/nvd'
import './App.css'

type SeverityFilter = 'ALL' | Severity

const PAGE_SIZE = 12
const severityFilters: SeverityFilter[] = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

function formatDate(value: string) {
  return new Intl.DateTimeFormat('pt-BR', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}

function severityLabel(severity: SeverityFilter) {
  return severity === 'ALL' ? 'Todas' : severity
}

function App() {
  const [searchInput, setSearchInput] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [days, setDays] = useState(30)
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('ALL')
  const [page, setPage] = useState(0)
  const [refreshKey, setRefreshKey] = useState(0)
  const [records, setRecords] = useState<CveRecord[]>([])
  const [totalResults, setTotalResults] = useState(0)
  const [updatedAt, setUpdatedAt] = useState('')
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedCve, setSelectedCve] = useState<CveRecord | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    fetchCves({
      query: searchTerm,
      days,
      startIndex: page * PAGE_SIZE,
      resultsPerPage: PAGE_SIZE,
      signal: controller.signal,
    })
      .then((result) => {
        setRecords(result.vulnerabilities)
        setTotalResults(result.totalResults)
        setUpdatedAt(result.updatedAt)
      })
      .catch((cause: unknown) => {
        if (cause instanceof DOMException && cause.name === 'AbortError') return
        setRecords([])
        setTotalResults(0)
        setError(cause instanceof Error ? cause.message : 'Não foi possível consultar a NVD.')
      })
      .finally(() => {
        if (!controller.signal.aborted) setIsLoading(false)
      })

    return () => controller.abort()
  }, [searchTerm, days, page, refreshKey])

  const visibleRecords = useMemo(
    () =>
      severityFilter === 'ALL'
        ? records
        : records.filter((record) => record.severity === severityFilter),
    [records, severityFilter],
  )

  const pageCriticalCount = records.filter((record) => record.severity === 'CRITICAL').length
  const pageHighCount = records.filter((record) => record.severity === 'HIGH').length
  const pageCount = Math.max(1, Math.ceil(totalResults / PAGE_SIZE))

  function prepareQuery() {
    setIsLoading(true)
    setError('')
  }

  function submitSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    prepareQuery()
    setPage(0)
    const nextSearch = searchInput.trim()
    if (nextSearch === searchTerm && page === 0) setRefreshKey((value) => value + 1)
    else setSearchTerm(nextSearch)
  }

  function updateDays(value: string) {
    prepareQuery()
    setDays(Number(value))
    setPage(0)
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#" aria-label="VulnRadar, início">
          <span className="brand-mark" aria-hidden="true">
            <RadarIcon />
          </span>
          <span>VULN<span className="brand-light">RADAR</span></span>
        </a>
        <div className="topbar-right">
          <span className="source-status"><span className="status-dot" /> Dados públicos da NVD</span>
          <a className="top-link" href="https://nvd.nist.gov/" target="_blank" rel="noreferrer">
            Sobre a NVD <ExternalIcon />
          </a>
        </div>
      </header>

      <main className="main-content">
        <section className="intro">
          <div className="eyebrow"><span className="eyebrow-line" /> THREAT INTELLIGENCE · CVE TRACKER</div>
          <div className="intro-row">
            <div>
              <h1>Vulnerabilidades,<br /><span>sob controle.</span></h1>
              <p className="intro-copy">
                Pesquise e acompanhe vulnerabilidades conhecidas em um só lugar.
                Dados atualizados diretamente da base oficial NVD.
              </p>
            </div>
            <div className="intro-aside">
              <span className="aside-label">FONTE DE DADOS</span>
              <strong>NIST National Vulnerability Database</strong>
              <span>Atualização em tempo real · API 2.0</span>
            </div>
          </div>
        </section>

        <section className="search-panel" aria-label="Busca de vulnerabilidades">
          <form className="search-form" onSubmit={submitSearch}>
            <SearchIcon />
            <input
              aria-label="Buscar por CVE, produto ou fornecedor"
              placeholder="Buscar por CVE, produto ou fornecedor..."
              value={searchInput}
              onChange={(event) => setSearchInput(event.target.value)}
            />
            {searchInput && (
              <button
                className="clear-search"
                type="button"
                aria-label="Limpar busca"
                onClick={() => {
                  prepareQuery()
                  setSearchInput('')
                  if (searchTerm === '' && page === 0) setRefreshKey((value) => value + 1)
                  setSearchTerm('')
                  setPage(0)
                }}
              >
                ×
              </button>
            )}
            <button className="search-button" type="submit">Buscar <span>↗</span></button>
          </form>
          <div className="search-options">
            <span>PERÍODO DE PUBLICAÇÃO</span>
            <select aria-label="Período de publicação" value={days} onChange={(event) => updateDays(event.target.value)}>
              <option value={7}>Últimos 7 dias</option>
              <option value={30}>Últimos 30 dias</option>
              <option value={90}>Últimos 90 dias</option>
            </select>
            <span className="search-hint">Dica: experimente “Windows”, “Apache” ou “CVE-2026-12345”</span>
          </div>
        </section>

        <section className="overview" aria-label="Resumo dos resultados">
          <div className="overview-heading">
            <div>
              <span className="section-kicker">MONITORAMENTO</span>
              <h2>{searchTerm ? 'Resultados da busca' : 'CVEs recentes'}</h2>
            </div>
            <span className="last-updated"><span className="live-dot" /> {updatedAt ? `NVD · ${formatDate(updatedAt)}` : 'CONSULTANDO NVD'}</span>
          </div>

          <div className="stats-grid">
            <StatCard label="VULNERABILIDADES ENCONTRADAS" value={isLoading ? '—' : totalResults.toLocaleString('pt-BR')} detail={`${days} dias · NVD`} icon={<LayersIcon />} />
            <StatCard label="CRÍTICAS NESTA PÁGINA" value={isLoading ? '—' : String(pageCriticalCount).padStart(2, '0')} detail="CVSS 9.0 – 10.0" tone="critical" icon={<AlertIcon />} />
            <StatCard label="ALTAS NESTA PÁGINA" value={isLoading ? '—' : String(pageHighCount).padStart(2, '0')} detail="CVSS 7.0 – 8.9" tone="high" icon={<PulseIcon />} />
          </div>
        </section>

        <section className="results-section" aria-label="Lista de vulnerabilidades">
          <div className="results-toolbar">
            <div className="filter-tabs" role="group" aria-label="Filtrar por severidade">
              {severityFilters.map((filter) => (
                <button
                  className={`filter-tab ${severityFilter === filter ? 'active' : ''} ${filter !== 'ALL' ? `filter-${filter.toLowerCase()}` : ''}`}
                  key={filter}
                  type="button"
                  aria-pressed={severityFilter === filter}
                  onClick={() => setSeverityFilter(filter)}
                >
                  {severityLabel(filter)}
                </button>
              ))}
            </div>
            <span className="result-count">
              {isLoading ? 'Consultando NVD...' : `${visibleRecords.length} ${visibleRecords.length === 1 ? 'resultado nesta página' : 'resultados nesta página'}`}
            </span>
          </div>

          {error ? (
            <div className="state-card error-state" role="alert">
              <span className="state-icon"><AlertIcon /></span>
              <h3>Não foi possível carregar os dados</h3>
              <p>{error}</p>
              <button className="retry-button" type="button" onClick={() => {
                prepareQuery()
                setRefreshKey((value) => value + 1)
              }}>Tentar novamente</button>
            </div>
          ) : isLoading ? (
            <div className="state-card loading-state" role="status">
              <span className="spinner" />
              <strong>Consultando a base NVD</strong>
              <span>Buscando vulnerabilidades recentes...</span>
            </div>
          ) : visibleRecords.length === 0 ? (
            <div className="state-card">
              <span className="state-icon"><SearchIcon /></span>
              <h3>Nenhuma vulnerabilidade encontrada</h3>
              <p>Tente outro termo ou ajuste o período e o filtro de severidade.</p>
            </div>
          ) : (
            <div className="cve-list">
              {visibleRecords.map((record) => (
                <button className="cve-row" key={record.id} type="button" onClick={() => setSelectedCve(record)}>
                  <span className={`severity-rail severity-${record.severity.toLowerCase()}`} />
                  <span className="cve-main">
                    <span className="cve-row-top">
                      <strong className="cve-id">{record.id}</strong>
                      <SeverityBadge severity={record.severity} />
                    </span>
                    <span className="cve-description">{record.description || 'Descrição não disponível em português ou inglês.'}</span>
                    <span className="cve-meta">
                      <span><CalendarIcon /> {formatDate(record.published)}</span>
                      {record.cwes.length > 0 && <span className="cwe-tag">{record.cwes[0]}</span>}
                      {record.affectedProducts.length > 0 && <span className="product-tag">{record.affectedProducts[0]}</span>}
                    </span>
                  </span>
                  <span className="score-block">
                    <span className="score-value">{record.score === null ? '—' : record.score.toFixed(1)}</span>
                    <span className="score-label">CVSS</span>
                  </span>
                  <span className="row-arrow" aria-hidden="true">↗</span>
                </button>
              ))}
            </div>
          )}

          {!isLoading && !error && totalResults > PAGE_SIZE && (
            <div className="pagination">
              <span>Exibindo página <strong>{page + 1}</strong> de <strong>{pageCount.toLocaleString('pt-BR')}</strong></span>
              <div className="pagination-actions">
                <button type="button" disabled={page === 0} onClick={() => {
                  prepareQuery()
                  setPage((value) => Math.max(0, value - 1))
                }}>← Anterior</button>
                <button type="button" disabled={(page + 1) * PAGE_SIZE >= totalResults} onClick={() => {
                  prepareQuery()
                  setPage((value) => value + 1)
                }}>Próxima →</button>
              </div>
            </div>
          )}
        </section>
      </main>

      <footer className="footer">
        <span>© 2026 VulnRadar <span className="footer-separator">·</span> Feito para quem protege.</span>
        <span>Dados fornecidos por <a href="https://nvd.nist.gov/" target="_blank" rel="noreferrer">NIST NVD <ExternalIcon /></a></span>
      </footer>

      {selectedCve && <CveDetails record={selectedCve} onClose={() => setSelectedCve(null)} />}
    </div>
  )
}

function StatCard({
  label,
  value,
  detail,
  icon,
  tone = '',
}: {
  label: string
  value: string
  detail: string
  icon: ReactNode
  tone?: string
}) {
  return (
    <div className={`stat-card ${tone}`}>
      <div className="stat-top"><span>{label}</span><span className="stat-icon">{icon}</span></div>
      <strong className="stat-value">{value}</strong>
      <span className="stat-detail">{detail}</span>
    </div>
  )
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity-badge severity-${severity.toLowerCase()}`}><span />{severity}</span>
}

function CveDetails({ record, onClose }: { record: CveRecord; onClose: () => void }) {
  return (
    <div className="modal-backdrop" onMouseDown={(event) => {
      if (event.target === event.currentTarget) onClose()
    }}>
      <section className="details-modal" role="dialog" aria-modal="true" aria-labelledby="details-title">
        <div className="modal-top">
          <span className="section-kicker">DETALHES DA VULNERABILIDADE</span>
          <button type="button" className="modal-close" aria-label="Fechar detalhes" onClick={onClose}>×</button>
        </div>
        <div className="modal-title-row">
          <h2 id="details-title">{record.id}</h2>
          <SeverityBadge severity={record.severity} />
        </div>
        <p className="modal-description">{record.description || 'Descrição não disponível em português ou inglês.'}</p>
        <div className="detail-grid">
          <DetailItem label="CVSS BASE" value={record.score === null ? 'Não informado' : `${record.score.toFixed(1)}${record.vector ? ` · ${record.vector}` : ''}`} />
          <DetailItem label="PUBLICADA EM" value={formatDate(record.published)} />
          <DetailItem label="ÚLTIMA ATUALIZAÇÃO" value={formatDate(record.lastModified)} />
          <DetailItem label="CWE" value={record.cwes.length ? record.cwes.join(', ') : 'Não informado'} />
        </div>
        <div className="detail-products">
          <span className="section-kicker">PRODUTOS AFETADOS IDENTIFICADOS</span>
          {record.affectedProducts.length ? (
            <div className="product-list">{record.affectedProducts.map((product) => <span key={product}>{product}</span>)}</div>
          ) : <p>Consulte os detalhes de configuração na página oficial da NVD.</p>}
        </div>
        <div className="detail-products">
          <span className="section-kicker">REFERÊNCIAS OFICIAIS</span>
          {record.references.length ? (
            <div className="product-list">
              {record.references.slice(0, 5).map((reference) => (
                <a key={reference} href={reference} target="_blank" rel="noreferrer">{reference}</a>
              ))}
            </div>
          ) : <p>Não há referências informadas neste registro.</p>}
        </div>
        <a className="nvd-button" href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(record.id)}`} target="_blank" rel="noreferrer">
          Abrir registro completo na NVD <ExternalIcon />
        </a>
      </section>
    </div>
  )
}

function DetailItem({ label, value }: { label: string; value: string }) {
  return <div className="detail-item"><span>{label}</span><strong>{value}</strong></div>
}

function RadarIcon() {
  return <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 12 20.5 4M12 4a8 8 0 1 0 8 8M12 8a4 4 0 1 0 4 4" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" /><circle cx="12" cy="12" r="1.3" fill="currentColor" /></svg>
}

function SearchIcon() {
  return <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="10.8" cy="10.8" r="6.8" stroke="currentColor" strokeWidth="1.7" /><path d="m16 16 4.2 4.2" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" /></svg>
}

function ExternalIcon() {
  return <svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M9 3h4v4M13 3 7 9M12 9v3a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" /></svg>
}

function LayersIcon() {
  return <svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="m10 2 7 4-7 4-7-4 7-4ZM3 10l7 4 7-4M3 14l7 4 7-4" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" /></svg>
}

function AlertIcon() {
  return <svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M10 3 18 17H2L10 3Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" /><path d="M10 8v4m0 2v.1" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></svg>
}

function PulseIcon() {
  return <svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M2 10h4l2-5 4 10 2-5h4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
}

function CalendarIcon() {
  return <svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="2.25" y="3.5" width="11.5" height="10" rx="1.4" stroke="currentColor" strokeWidth="1.2" /><path d="M5 2v3M11 2v3M2.5 6.5h11" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" /></svg>
}

export default App
