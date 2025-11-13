## Dados usados pelo notebook de análise de rede e vulnerabilidades

Este repositório contém dois datasets principais que alimentam as análises de rede (dependências) e de vulnerabilidades (CWEs) do notebook `vulnerability_network_analysis.ipynb`.

- `python_dependencies_edges.csv`: grafo de dependências entre pacotes PyPI.
- `outputs/top_pypi_snyk_timeline_20231101_20251101.csv`: linha do tempo de vulnerabilidades (CVE/CWE) consolidada, usada para métricas temporais e análises por CWE.

Os exemplos abaixo mostram como carregar os dados e um resumo das colunas de cada arquivo.

---

### 1) python_dependencies_edges.csv
Grafo direcionado “pacote → depende de”.

#### Colunas
- `source` (str): pacote de origem. É quem “depende de” outro pacote (ex.: `langchain`).
- `target` (str): pacote de destino. É o pacote requerido pelo `source` (ex.: `pydantic`).

Observações
- O grafo é direcionado. Um caminho `A → B → C` indica que `A` depende (direta ou indiretamente) de `C`.
- Os nomes de pacotes estão em minúsculas para facilitar junções.

---

### 2) outputs/top_pypi_snyk_timeline_20231101_20251101.csv
Linha do tempo de vulnerabilidades (com CWEs) para pacotes PyPI. É o dataset usado para filtrar períodos (ex.: `--start 2023-11-01 --end 2025-11-01`) e para calcular métricas como tempo de correção e influência de CWE.

#### Colunas
- `package` (str): nome do pacote afetado (ex.: `pillow`, `torch`, `transformers`).
- `cve` (str): identificador CVE quando disponível (ex.: `CVE-2024-…`). Pode estar vazio em alguns registros.
- `cwes` (str): lista de CWEs separados por `;`, `,` ou espaço (ex.: `CWE-79;CWE-89`). Pode estar vazia.
- `severity` (str): severidade da vulnerabilidade (ex.: `low`, `medium`, `high`, `critical`, `unknown`).
- `first_affected_version` (str): versão introduzida vulnerável (quando identificada).
- `first_affected_date` (date): data em que a versão vulnerável entrou no ecossistema (quando disponível).
- `disclosed_date` (date): data de divulgação pública da vulnerabilidade.
- `mitigation_version` (str): primeira versão que contém o “fix”/mitigação.
- `mitigation_date` (date): data associada à versão de mitigação (ex.: release fix).
- `disclosure_lag_days` (float): diferença (em dias) entre `disclosed_date` e `first_affected_date`. Valores negativos indicam correção anterior à divulgação pública.
- `time_to_fix_from_first_days` (float): tempo (em dias) entre `first_affected_date` e `mitigation_date`. Negativo quando o fix precede a data estimada de introdução.
- `time_to_fix_from_disclosure_days` (float): tempo (em dias) entre `disclosed_date` e `mitigation_date`. `0` ou valores próximos de `0` indicam correção no mesmo dia; negativos indicam correção antes da divulgação.
- `fix_semver_type` (str): tipo de incremento semântico do fix (ex.: `patch`, `minor`, `major`).

Observações
- `cwes` é normalizada no notebook para listas (`cwe_list`). Ex.: `["CWE-79", "CWE-89"]`.
- Métricas de tempo podem ser negativas quando a correção saiu antes da data de referência (comum em backports/ajustes de data).

---



### Nota sobre uso no notebook
- O arquivo de dependências é usado para calcular:
  - alcance de dependentes (diretos/indiretos),
  - profundidade média de propagação (média dos níveis de “hops” em BFS reverso),
  - métricas de centralidade (grau de entrada/saída).
- A timeline é usada para:
  - unir pacotes às suas CWEs,
  - fazer recortes temporais,
  - calcular tempos de correção e construir o grafo de co‑ocorrência/causalidade de CWEs (influência). 

---

## Exemplo de “head do pandas” (saída esperada resumida)

`python_dependencies_edges.csv` (head):
```
  source   target
0  agno    aiohttp
1  agno    opentelemetry-exporter-otlp-proto-grpc
2  agno    typing-extensions
3  agno    mem0ai
4  agno    google-genai
```

`top_pypi_snyk_timeline_20231101_20251101.csv` (head):
```
     package        cve          cwes severity first_affected_version first_affected_date disclosed_date ...
0   urllib3  CVE-2024-...      CWE-669     low                     0                NaT      2024-06-17 ...
1   urllib3  CVE-2025-...      CWE-601     low                  2.2.0         2024-01-30      2025-06-18 ...
2   urllib3  CVE-2023-...      CWE-200     low                     0                NaT      2023-10-17 ...
3   urllib3  CVE-2018-...      CWE-601     low                     0                NaT      2023-10-15 ...
4   urllib3  CVE-2025-...      CWE-601     low                     0                NaT      2025-06-18 ...
```