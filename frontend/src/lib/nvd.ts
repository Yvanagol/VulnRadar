export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'

export interface CveRecord {
  id: string
  description: string
  published: string
  lastModified: string
  score: number | null
  severity: Severity
  vector: string | null
  cwes: string[]
  affectedProducts: string[]
  references: string[]
}

export interface CveSearchResult {
  totalResults: number
  vulnerabilities: CveRecord[]
  source: string
  updatedAt: string
}

interface FetchCvesOptions {
  query: string
  days: number
  startIndex: number
  resultsPerPage: number
  signal: AbortSignal
}

export async function fetchCves({
  query,
  days,
  startIndex,
  resultsPerPage,
  signal,
}: FetchCvesOptions): Promise<CveSearchResult> {
  const params = new URLSearchParams({
    days: String(days),
    startIndex: String(startIndex),
    resultsPerPage: String(resultsPerPage),
  })

  if (query.trim()) params.set('query', query.trim())

  const response = await fetch(`/api/cves?${params.toString()}`, {
    headers: { Accept: 'application/json' },
    signal,
  })

  if (!response.ok) {
    const data = (await response.json()) as { error?: string }
    throw new Error(data.error ?? `A consulta falhou (HTTP ${response.status}). Tente novamente em instantes.`)
  }

  return (await response.json()) as CveSearchResult
}
