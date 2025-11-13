#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Top PyPI Packages → Vulnerability analysis with Snyk Vulnerability Database + PyPI
-----------------------------------------------------------------------------------
Fetches vulnerability data from Snyk's public Vulnerability Database for top PyPI packages
and analyzes time-to-fix, CWEs, severity distribution, and survival curves.
"""
import argparse, csv, json, math, os, re, time
from datetime import datetime, date, timedelta, timezone
from typing import Dict, Optional, List, Tuple

import pandas as pd
import requests
from dateutil.relativedelta import relativedelta
from packaging.version import Version, InvalidVersion
from packaging.utils import canonicalize_name

from scipy.stats import mannwhitneyu
from lifelines import KaplanMeierFitter
import matplotlib.pyplot as plt

TOP_JSON = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
TOP_CSV  = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.csv"
PYPI_JSON = "https://pypi.org/pypi/{package}/json"
SNYK_BASE = "https://api.snyk.io/rest"
SNYK_VER  = "2024-10-15"  # Try also: 2024-09-04, 2024-06-10

def ensure_dirs(base="outputs"):
    os.makedirs(base, exist_ok=True)
    os.makedirs(os.path.join(base, "summaries"), exist_ok=True)
    os.makedirs(os.path.join(base, "plots"), exist_ok=True)
    os.makedirs(os.path.join(base, "downloads"), exist_ok=True)

def pdate(x) -> Optional[date]:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return None
    s = str(x).strip()
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace('Z', '+00:00')).date()
    except Exception:
        pass
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(s, fmt).date()
        except Exception:
            continue
    return None

def get_pypi_release_dates(package: str) -> Dict[str, date]:
    try:
        r = requests.get(PYPI_JSON.format(package=package), timeout=20)
        if r.status_code != 200:
            return {}
        data = r.json()
    except Exception:
        return {}
    out = {}
    for ver, files in (data.get("releases") or {}).items():
        dates: List[date] = []
        for f in files or []:
            ts = f.get("upload_time_iso_8601") or f.get("upload_time")
            d = pdate(ts)
            if d:
                dates.append(d)
        if dates:
            out[ver] = min(dates)
    return out

def parse_fixed_version(row: dict) -> Optional[str]:
    candidates = set()
    for col in ["FIXED_IN_VERSION", "fixed_in", "first_patched_version", "patched_versions"]:
        val = row.get(col)
        if val is None or (isinstance(val, float) and math.isnan(val)):
            continue
        if isinstance(val, list):
            for v in val:
                if v:
                    candidates.add(str(v).strip())
        else:
            s = str(val)
            try:
                jj = json.loads(s)
                if isinstance(jj, list):
                    for v in jj:
                        if v:
                            candidates.add(str(v).strip())
                elif isinstance(jj, dict):
                    x = jj.get("identifier") or jj.get("version")
                    if x:
                        candidates.add(str(x).strip())
            except Exception:
                for v in re.split(r"[,\s]+", s):
                    if v:
                        candidates.add(v.strip())
    norm = []
    for v in candidates:
        try:
            norm.append(Version(v))
        except InvalidVersion:
            continue
    if not norm:
        return None
    return str(min(norm))

def extract_cwes(row: dict) -> Optional[List[str]]:
    cwes = set()
    for col in ["CWE", "cwe", "cwes"]:
        v = row.get(col)
        if v is None:
            continue
        if isinstance(v, list):
            for x in v:
                if isinstance(x, str):
                    cwes.update(re.findall(r"CWE-\d+", x.upper()))
        else:
            cwes.update(re.findall(r"CWE-\d+", str(v).upper()))
    for col in ["references", "urls", "referencesUrl", "source", "advisory_urls"]:
        v = row.get(col)
        if v is None:
            continue
        if isinstance(v, list):
            for x in v:
                if isinstance(x, str):
                    cwes.update(re.findall(r"CWE-\d+", x.upper()))
        else:
            cwes.update(re.findall(r"CWE-\d+", str(v).upper()))
    return sorted(cwes) if cwes else None

def semver_bump(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if not a or not b:
        return None
    try:
        v0, v1 = Version(a), Version(b)
    except Exception:
        return None
    if v0.major != v1.major:
        return "major"
    if v0.minor != v1.minor:
        return "minor"
    if v0.micro != v1.micro:
        return "patch"
    return "same"

def estimate_first_affected_version(row: dict) -> Optional[str]:
    for col in ["SEMVER_VULNERABLE_RANGE", "vulnerable_versions", "vulnerable_range", "affected_range", "semver_vulnerable"]:
        s = row.get(col)
        if not s or (isinstance(s, float) and math.isnan(s)):
            continue
        txt = str(s)
        lows = re.findall(r">=\s*([0-9A-Za-z\.\-\+]+)", txt)
        valids = []
        for x in lows:
            try:
                valids.append(Version(x))
            except InvalidVersion:
                pass
        if valids:
            return str(min(valids))
    return None

def fetch_top_packages(top_file: Optional[str]=None, limit:int=5000) -> List[str]:
    print(f"📦 Buscando top {limit} pacotes PyPI...")
    pkgs = []
    if top_file:
        print(f"   Lendo arquivo local: {top_file}")
        if top_file.endswith(".csv"):
            df = pd.read_csv(top_file)
            name_col = "project" if "project" in df.columns else "name"
            pkgs = df[name_col].astype(str).tolist()
        else:
            with open(top_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            rows = data.get("rows") if isinstance(data, dict) else data
            for r in rows:
                pkgs.append(r.get("project") or r.get("name"))
    else:
        print(f"   Baixando de: {TOP_JSON}")
        r = requests.get(TOP_JSON, timeout=30); r.raise_for_status()
        data = r.json()
        rows = data.get("rows") if isinstance(data, dict) else data
        for rj in rows:
            name = rj.get("project") or rj.get("name")
            if name:
                pkgs.append(name)
    pkgs = [canonicalize_name(p) for p in pkgs if p]
    seen = set(); out = []
    for p in pkgs:
        if p not in seen:
            seen.add(p); out.append(p)
        if len(out) >= limit:
            break
    print(f"✅ {len(out)} pacotes únicos carregados")
    return out

def test_snyk_auth(token: str, org_or_group_id: str, use_org: bool = False) -> bool:
    """Test if the Snyk token and ID are valid."""
    sess = requests.Session()
    sess.headers.update({"Authorization": f"token {token}"})
    
    # Try to get group/org info
    entity_type = "orgs" if use_org else "groups"
    test_url = f"{SNYK_BASE}/{entity_type}/{org_or_group_id}"
    
    try:
        print(f"🔍 Testando autenticação com {entity_type}/{org_or_group_id}...")
        r = sess.get(test_url, params={"version": SNYK_VER})
        if r.status_code == 200:
            print(f"✅ Autenticação bem-sucedida!")
            return True
        elif r.status_code == 404:
            print(f"⚠️  {entity_type.upper()} ID não encontrado (404)")
            print(f"   Você pode estar usando um {entity_type[:-1].upper()} ID errado")
            print(f"   Ou deveria usar --use-org-id em vez de --snyk-group-id" if not use_org else "   Ou deveria usar --snyk-group-id em vez de --use-org-id")
            return False
        elif r.status_code == 401:
            print(f"❌ Token inválido ou expirado (401)")
            return False
        else:
            print(f"⚠️  Resposta inesperada: {r.status_code}")
            print(f"   {r.text[:200]}")
            return False
    except Exception as e:
        print(f"❌ Erro ao testar autenticação: {e}")
        return False

def fetch_snyk_vulnerabilities_export(token: str, org_id: str, start: date, end: date, out_dir="outputs") -> str:
    """
    Export ALL PyPI vulnerabilities from Snyk Database using Export API.
    Uses POST /rest/orgs/{orgId}/export/requests endpoint.
    Returns CSV with complete CWE, CVE, CVSS, exploit maturity, and all attributes.
    """
    print(f"\n🔍 Exportando TODAS as vulnerabilidades PyPI do Snyk Database...")
    print(f"   📅 Período: {start} até {end}")
    
    sess = requests.Session()
    sess.headers.update({
        "Authorization": f"token {token}",
        "Content-Type": "application/json"
    })
    
    # Payload para exportar vulnerabilidades PyPI
    payload = {
          "filters": {
            "ecosystems": ["pypi"],
            "vulnAttributes": [
                "id", "cve", "cwe", "cvssScore", "cvssVector",
                "title", "description", "published", "disclosed",
                "introducedThrough", "fixedIn", "exploitMaturity",
                "semver", "credit", "references"
            ],
            "time": {
                "from": f"{start}T00:00:00Z",
                "to": f"{end}T23:59:59Z"
            }
        },
        "format": "csv"
    }
    
    # Create export request
    export_url = f"{SNYK_BASE}/orgs/{org_id}/export/requests"
    print(f"   🔄 Criando job de export...")
    
    try:
        r = sess.post(export_url, params={"version": SNYK_VER}, json=payload)
        r.raise_for_status()
        export_data = r.json()
        export_id = export_data.get("data", {}).get("id")
        
        if not export_id:
            raise RuntimeError(f"Export ID não encontrado na resposta: {export_data}")
        
        print(f"   ✅ Export criado com ID: {export_id}")
        
        # Poll for completion
        status_url = f"{SNYK_BASE}/orgs/{org_id}/export/requests/{export_id}"
        print(f"   ⏳ Aguardando processamento...")
        
        max_attempts = 60  # 5 minutes max
        attempt = 0
        
        while attempt < max_attempts:
            time.sleep(5)
            attempt += 1
            
            status_r = sess.get(status_url, params={"version": SNYK_VER})
            status_r.raise_for_status()
            status_data = status_r.json()
            
            status = status_data.get("data", {}).get("attributes", {}).get("status")
            print(f"   📊 Status: {status} (tentativa {attempt}/{max_attempts})")
            
            if status == "complete":
                # Get download URL
                download_url = status_data.get("data", {}).get("attributes", {}).get("downloadUrl")
                
                if not download_url:
                    raise RuntimeError("Download URL não encontrado")
                
                print(f"   📥 Baixando CSV...")
                csv_r = requests.get(download_url, timeout=120)
                csv_r.raise_for_status()
                
                out_csv = os.path.join(out_dir, "downloads", f"snyk_export_{export_id}.csv")
                with open(out_csv, "wb") as f:
                    f.write(csv_r.content)
                
                print(f"   ✅ CSV salvo: {out_csv}")
                
                # Show file size
                file_size = len(csv_r.content) / (1024 * 1024)
                print(f"   📦 Tamanho: {file_size:.2f} MB")
                
                return out_csv
                
            elif status in ["failed", "error"]:
                error_msg = status_data.get("data", {}).get("attributes", {}).get("error", "Unknown error")
                raise RuntimeError(f"Export falhou: {error_msg}")
        
        raise RuntimeError(f"Timeout aguardando export (>{max_attempts*5}s)")
        
    except requests.exceptions.HTTPError as e:
        print(f"   ❌ Erro HTTP: {e}")
        if hasattr(e.response, 'text'):
            print(f"   Resposta: {e.response.text[:500]}")
        raise
    except Exception as e:
        print(f"   ❌ Erro: {e}")
        raise

def fetch_combined_vulnerabilities(packages: List[str], start: date, end: date, nvd_api_key: str = None, out_dir="outputs") -> str:
    """
    Fetch vulnerabilities combining OSV (fast, has version ranges) + NVD (has CWE).
    Best of both worlds: speed + completeness.
    
    Args:
        nvd_api_key: NVD API key (50 req/30s vs 5 req/30s without key)
    """
    print(f"\n🔍 Consultando COMBINADO: OSV (versões) + NVD (CWE)...")
    print(f"   ✅ Melhor dos dois mundos: Rápido + CWE Completo")
    print(f"   📅 Período: {start} até {end}")
    
    if nvd_api_key:
        print(f"   🔑 API Key detectada: NVD rate limit = 50 req/30s (10x mais rápido!)")
    else:
        print(f"   ⚠️  Sem API Key: NVD rate limit = 5 req/30s (considere usar --nvd-api-key)")
    
    sess = requests.Session()
    
    # Add User-Agent (NVD recommends this)
    sess.headers.update({"User-Agent": "PyPI-Vulnerability-Research/1.0"})
    
    # NOTE: NVD API key should be query param, not header
    # But for now, we'll not use it as it seems to be invalid/expired
    
    # Step 1: Fetch from OSV (fast, has version info)
    print(f"\n   [Passo 1/2] Buscando vulnerabilidades do OSV...")
    osv_vulns = {}  # CVE -> vuln_data
    
    for idx, pkg in enumerate(packages, 1):
        print(f"   [{idx}/{len(packages)}] Consultando OSV: {pkg}")
        
        try:
            url = "https://api.osv.dev/v1/query"
            payload = {"package": {"name": pkg, "ecosystem": "PyPI"}}
            r = sess.post(url, json=payload, timeout=10)
            
            if r.status_code != 200:
                print(f"      ⚠️  Status {r.status_code}")
                continue
            
            data = r.json()
            vulns = data.get("vulns", [])
            
            if not vulns:
                print(f"      ℹ️  Nenhuma vulnerabilidade")
                time.sleep(0.1)
                continue
            
            pkg_cve_count = 0
            
            for vuln in vulns:
                vuln_id = vuln.get("id", "")
                
                # Get CVE from ID or aliases
                cve_id = None
                if vuln_id.startswith("CVE-"):
                    cve_id = vuln_id
                else:
                    for alias in vuln.get("aliases", []):
                        if alias.startswith("CVE-"):
                            cve_id = alias
                            break
                
                if not cve_id:
                    continue
                
                pkg_cve_count += 1
                
                # Extract version ranges and fixed versions
                affected = vuln.get("affected", [])
                vulnerable_range = []
                fixed_versions = []
                
                for aff in affected:
                    if aff.get("package", {}).get("name") == pkg:
                        for rng in aff.get("ranges", []):
                            if rng.get("type") == "ECOSYSTEM":
                                events = rng.get("events", [])
                                for event in events:
                                    if "introduced" in event:
                                        vulnerable_range.append(f">={event['introduced']}")
                                    if "fixed" in event:
                                        fixed_versions.append(event['fixed'])
                
                # Determine severity from CVSS if available
                severity = "unknown"
                cvss_score = None
                for sev_info in vuln.get("severity", []):
                    if sev_info.get("type") == "CVSS_V3":
                        score_str = sev_info.get("score")
                        if score_str and isinstance(score_str, str):
                            try:
                                # Parse CVSS vector to get score
                                import re
                                match = re.search(r'(\d+\.\d+)', score_str)
                                if match:
                                    cvss_score = float(match.group(1))
                                    if cvss_score >= 9.0:
                                        severity = "critical"
                                    elif cvss_score >= 7.0:
                                        severity = "high"
                                    elif cvss_score >= 4.0:
                                        severity = "medium"
                                    else:
                                        severity = "low"
                            except:
                                pass
                    break
                
                osv_vulns[cve_id] = {
                    "PROJECT_NAME": pkg,
                    "PROJECT_TYPE": "pip",
                    "PRODUCT_NAME": "Combined OSV+NVD",
                    "ISSUE_SEVERITY": severity,
                    "CVE": cve_id,
                    "CWE": None,  # Will be filled from NVD
                    "CVSS_SCORE": cvss_score,
                    "SEMVER_VULNERABLE_RANGE": " ".join(vulnerable_range) if vulnerable_range else None,
                    "FIXED_IN_VERSION": fixed_versions[0] if fixed_versions else None,
                    "VULNERABILITY_PUBLICATION_DATE": vuln.get("published"),
                    "FIRST_INTRODUCED": None,
                    "UPDATED_AT": vuln.get("modified"),
                    "DESCRIPTION": None
                }
            
            if pkg_cve_count > 0:
                print(f"      ✅ Encontradas {pkg_cve_count} CVEs")
            
            time.sleep(0.1)
            
        except Exception as e:
            print(f"      ⚠️  Erro: {e}")
            continue
    
    print(f"      ✅ OSV: {len(osv_vulns)} vulnerabilidades únicas encontradas")
    
    # Step 2: Enrich with CWE from NVD
    print(f"\n   [Passo 2/2] Enriquecendo {len(osv_vulns)} CVEs com CWE do NVD...")
    cve_list = list(osv_vulns.keys())
    
    # Adjust sleep time based on API key
    # Without key: 5 req/30s = 6s per request (use 7s to be safe)
    # NOTE: API key not working currently, always use slow rate
    sleep_time = 7.0
    cwe_found = 0
    
    if nvd_api_key:
        print(f"   ⚠️  API Key fornecida mas NÃO está sendo usada (problema de autenticação)")
        print(f"   📊 Usando rate limit público: 5 req/30s (~7s por CVE)")
    
    for idx, cve_id in enumerate(cve_list, 1):
        print(f"   [{idx}/{len(cve_list)}] Enriquecendo: {cve_id}")
        
        try:
            # Query NVD by specific CVE
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {"cveId": cve_id}
            
            # Try up to 3 times for 404s (might be temporary)
            max_retries = 3
            for attempt in range(max_retries):
                r = sess.get(url, params=params, timeout=30)
                
                if r.status_code == 200:
                    break
                elif r.status_code == 403:
                    print(f"      ⚠️  Rate limit, aguardando...")
                    time.sleep(sleep_time * 2)
                    continue
                elif r.status_code == 404 and attempt < max_retries - 1:
                    # CVE might not be in NVD yet, wait and retry
                    time.sleep(sleep_time)
                    continue
                else:
                    break
            
            if r.status_code != 200:
                if r.status_code == 404:
                    print(f"      ℹ️  CVE não encontrada no NVD (pode ser muito recente)")
                else:
                    print(f"      ⚠️  Status {r.status_code}")
                time.sleep(sleep_time)
                continue
            
            data = r.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if vulnerabilities:
                cve = vulnerabilities[0].get("cve", {})
                
                # Extract CWEs
                cwes = []
                weaknesses = cve.get("weaknesses", [])
                for weakness in weaknesses:
                    for desc in weakness.get("description", []):
                        cwe_id = desc.get("value")
                        if cwe_id and cwe_id.startswith("CWE-"):
                            cwes.append(cwe_id)
                
                if cwes:
                    osv_vulns[cve_id]["CWE"] = ";".join(set(cwes))
                    cwe_found += 1
                    print(f"      ✅ CWE: {', '.join(set(cwes))}")
                else:
                    print(f"      ℹ️  Sem CWE")
                
                # Update CVSS if not present
                if not osv_vulns[cve_id]["CVSS_SCORE"]:
                    metrics = cve.get("metrics", {})
                    for cvss_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if cvss_version in metrics and metrics[cvss_version]:
                            cvss_data = metrics[cvss_version][0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore")
                            if cvss_score:
                                osv_vulns[cve_id]["CVSS_SCORE"] = cvss_score
                                severity = cvss_data.get("baseSeverity", "").lower()
                                if severity:
                                    osv_vulns[cve_id]["ISSUE_SEVERITY"] = severity
                            break
            
            time.sleep(sleep_time)  # NVD rate limit
            
        except Exception as e:
            print(f"      ⚠️  Erro: {e}")
            time.sleep(sleep_time)
            continue
    
    # Filter by date and save
    all_vulns = []
    for vuln_data in osv_vulns.values():
        pub_date = pdate(vuln_data.get("VULNERABILITY_PUBLICATION_DATE"))
        if pub_date and start <= pub_date <= end:
            all_vulns.append(vuln_data)
    
    print(f"\n" + "=" * 60)
    print(f"✅ RESUMO:")
    print(f"   📊 Total de vulnerabilidades (após filtro de data): {len(all_vulns)}")
    print(f"   🔍 CVEs com CWE: {sum(1 for v in all_vulns if v.get('CWE'))} de {len(all_vulns)} ({sum(1 for v in all_vulns if v.get('CWE'))*100//len(all_vulns) if all_vulns else 0}%)")
    print(f"   📈 CVEs com CVSS: {sum(1 for v in all_vulns if v.get('CVSS_SCORE'))} de {len(all_vulns)}")
    print("=" * 60)
    
    if not all_vulns:
        print("⚠️  Nenhuma vulnerabilidade no período")
        df = pd.DataFrame(columns=["PROJECT_NAME", "PROJECT_TYPE", "PRODUCT_NAME", "ISSUE_SEVERITY", 
                                   "CVE", "CWE", "CVSS_SCORE", "SEMVER_VULNERABLE_RANGE", "FIXED_IN_VERSION",
                                   "VULNERABILITY_PUBLICATION_DATE", "FIRST_INTRODUCED", "UPDATED_AT", "DESCRIPTION"])
        out_csv = os.path.join(out_dir, "downloads", f"combined_vulns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        df.to_csv(out_csv, index=False)
        return out_csv
    
    df = pd.DataFrame(all_vulns)
    out_csv = os.path.join(out_dir, "downloads", f"combined_vulns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    df.to_csv(out_csv, index=False)
    
    file_size = os.path.getsize(out_csv) / 1024
    print(f"\n💾 Arquivo salvo: {out_csv}")
    print(f"📦 Tamanho: {file_size:.1f} KB")
    
    return out_csv

def fetch_nvd_vulnerabilities(packages: List[str], start: date, end: date, nvd_api_key: str = None, out_dir="outputs") -> str:
    """
    Fetch vulnerabilities from NVD (National Vulnerability Database) API.
    NVD has COMPLETE CWE, CVE, CVSS data - free API with rate limits.
    
    Args:
        nvd_api_key: NVD API key (50 req/30s vs 5 req/30s without key)
    """
    print(f"\n🔍 Consultando NVD Database (NIST) para {len(packages)} pacotes...")
    print(f"   ✅ NVD TEM CWE COMPLETO + CVE + CVSS")
    print(f"   📅 Período: {start} até {end}")
    
    if nvd_api_key:
        print(f"   🔑 API Key detectada: NVD rate limit = 50 req/30s")
    else:
        print(f"   ⚠️  Sem API Key: NVD rate limit = 5 req/30s")
    
    sess = requests.Session()
    sess.headers.update({"User-Agent": "PyPI-Vulnerability-Research/1.0"})
    
    # NOTE: API key not working currently, always use slow rate
    sleep_time = 7.0
    all_vulns = []
    
    if nvd_api_key:
        print(f"   ⚠️  API Key fornecida mas NÃO está sendo usada (problema de autenticação)")
        print(f"   📊 Usando rate limit público: 5 req/30s (~7s por requisição)")
    
    for idx, pkg in enumerate(packages, 1):
        print(f"   [{idx}/{len(packages)}] Consultando: {pkg}")
        
        try:
            # NVD API 2.0 - search by keyword (package name)
            # Note: NVD doesn't support date filtering well, so we fetch all and filter later
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            
            params = {
                "keywordSearch": f"python {pkg}",
                "resultsPerPage": 100
            }
            
            r = sess.get(url, params=params, timeout=30)
            
            if r.status_code == 403:
                print(f"      ⚠️  Rate limit atingido. Aguardando...")
                time.sleep(sleep_time)
                r = sess.get(url, params=params, timeout=30)
            
            if r.status_code != 200:
                print(f"      ⚠️  Status {r.status_code}")
                time.sleep(sleep_time)  # NVD rate limit
                continue
            
            data = r.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if vulnerabilities:
                print(f"      ✅ Encontradas {len(vulnerabilities)} vulnerabilidades")
            
            for vuln_item in vulnerabilities:
                cve = vuln_item.get("cve", {})
                cve_id = cve.get("id")
                
                # Extract CWEs
                cwes = []
                weaknesses = cve.get("weaknesses", [])
                for weakness in weaknesses:
                    for desc in weakness.get("description", []):
                        cwe_id = desc.get("value")
                        if cwe_id and cwe_id.startswith("CWE-"):
                            cwes.append(cwe_id)
                
                # Extract CVSS
                metrics = cve.get("metrics", {})
                cvss_score = None
                severity = "unknown"
                
                # Try CVSS v3.1 first, then v3.0, then v2.0
                for cvss_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if cvss_version in metrics and metrics[cvss_version]:
                        cvss_data = metrics[cvss_version][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        severity = cvss_data.get("baseSeverity", "").lower()
                        if not severity and cvss_score:
                            # Calculate severity from score
                            if cvss_score >= 9.0:
                                severity = "critical"
                            elif cvss_score >= 7.0:
                                severity = "high"
                            elif cvss_score >= 4.0:
                                severity = "medium"
                            else:
                                severity = "low"
                        break
                
                # Extract and filter dates
                published = cve.get("published")
                modified = cve.get("lastModified")
                
                # Filter by date range
                if published:
                    pub_date = pdate(published)
                    if pub_date and (pub_date < start or pub_date > end):
                        continue  # Skip vulnerabilities outside date range
                
                # Extract description
                descriptions = cve.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                vuln_data = {
                    "PROJECT_NAME": pkg,
                    "PROJECT_TYPE": "pip",
                    "PRODUCT_NAME": "NVD Database",
                    "ISSUE_SEVERITY": severity,
                    "CVE": cve_id,
                    "CWE": ";".join(set(cwes)) if cwes else None,
                    "CVSS_SCORE": cvss_score,
                    "SEMVER_VULNERABLE_RANGE": None,  # NVD doesn't have this
                    "FIXED_IN_VERSION": None,  # NVD doesn't have this
                    "VULNERABILITY_PUBLICATION_DATE": published,
                    "FIRST_INTRODUCED": None,
                    "UPDATED_AT": modified,
                    "DESCRIPTION": description[:200] if description else None
                }
                
                all_vulns.append(vuln_data)
            
            # NVD rate limit
            time.sleep(sleep_time)
            
        except Exception as e:
            print(f"   ⚠️  Erro ao processar {pkg}: {e}")
            time.sleep(sleep_time)
            continue
    
    print(f"\n✅ Total de vulnerabilidades encontradas: {len(all_vulns)}")
    
    # Save to CSV
    if not all_vulns:
        print("⚠️  Nenhuma vulnerabilidade encontrada")
        # Create empty CSV
        df = pd.DataFrame(columns=["PROJECT_NAME", "PROJECT_TYPE", "PRODUCT_NAME", "ISSUE_SEVERITY", 
                                   "CVE", "CWE", "CVSS_SCORE", "SEMVER_VULNERABLE_RANGE", "FIXED_IN_VERSION",
                                   "VULNERABILITY_PUBLICATION_DATE", "FIRST_INTRODUCED", "UPDATED_AT", "DESCRIPTION"])
        out_csv = os.path.join(out_dir, "downloads", f"nvd_vulns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        df.to_csv(out_csv, index=False)
        return out_csv
    
    df = pd.DataFrame(all_vulns)
    out_csv = os.path.join(out_dir, "downloads", f"nvd_vulns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    df.to_csv(out_csv, index=False)
    print(f"✅ Vulnerabilidades salvas em: {out_csv}")
    print(f"✅ CWEs encontradas: {df['CWE'].notna().sum()} de {len(df)} vulnerabilidades")
    
    return out_csv

def fetch_snyk_vulnerabilities_for_packages(token: str, packages: List[str], org_id: str, out_dir="outputs") -> str:
    """
    Fetch vulnerabilities using OSV (Open Source Vulnerabilities) API.
    This is a free, public API that aggregates vulnerability data including from Snyk.
    """
    print(f"\n🔍 Consultando OSV Database (Open Source Vulnerabilities) para {len(packages)} pacotes...")
    print(f"   ℹ️  OSV agrega dados de múltiplas fontes incluindo Snyk, GitHub, NVD, etc.")
    
    sess = requests.Session()
    all_vulns = []
    
    for idx, pkg in enumerate(packages, 1):
        if idx % 50 == 0:
            print(f"   Progresso: {idx}/{len(packages)} pacotes consultados")
        
        print(f"   [{idx}/{len(packages)}] Consultando: {pkg}")
        
        try:
            # Use OSV API - free and public
            url = "https://api.osv.dev/v1/query"
            payload = {
                "package": {
                    "name": pkg,
                    "ecosystem": "PyPI"
                }
            }
            r = sess.post(url, json=payload, timeout=10)
            
            if r.status_code != 200:
                print(f"      ⚠️  Status {r.status_code}")
                continue
            
            data = r.json()
            vulns = data.get("vulns", [])
            
            if vulns:
                print(f"      ✅ Encontradas {len(vulns)} vulnerabilidades")
            
            for vuln in vulns:
                # Extract vulnerability data from OSV API format
                vuln_id = vuln.get("id", "")
                
                # Determine severity
                severity = "unknown"
                if "database_specific" in vuln:
                    severity = vuln["database_specific"].get("severity", "unknown").lower()
                elif "severity" in vuln:
                    for sev_info in vuln.get("severity", []):
                        if sev_info.get("type") == "CVSS_V3":
                            score = sev_info.get("score")
                            if score:
                                severity = "critical" if float(score) >= 9.0 else "high" if float(score) >= 7.0 else "medium" if float(score) >= 4.0 else "low"
                
                # Extract affected ranges and fixed versions
                affected = vuln.get("affected", [])
                vulnerable_range = []
                fixed_versions = []
                
                for aff in affected:
                    if aff.get("package", {}).get("name") == pkg:
                        for rng in aff.get("ranges", []):
                            if rng.get("type") == "ECOSYSTEM":
                                events = rng.get("events", [])
                                for event in events:
                                    if "introduced" in event:
                                        vulnerable_range.append(f">={event['introduced']}")
                                    if "fixed" in event:
                                        fixed_versions.append(event['fixed'])
                
                vuln_data = {
                    "PROJECT_NAME": pkg,
                    "PROJECT_TYPE": "pip",
                    "PRODUCT_NAME": "OSV Database",
                    "ISSUE_SEVERITY": severity,
                    "CVE": vuln_id if vuln_id.startswith("CVE-") else None,
                    "CWE": None,  # OSV doesn't always have CWE
                    "SEMVER_VULNERABLE_RANGE": " ".join(vulnerable_range) if vulnerable_range else None,
                    "FIXED_IN_VERSION": fixed_versions[0] if fixed_versions else None,
                    "VULNERABILITY_PUBLICATION_DATE": vuln.get("published"),
                    "FIRST_INTRODUCED": None,
                    "UPDATED_AT": vuln.get("modified")
                }
                
                # Try to extract CVE from aliases if ID is not CVE
                if not vuln_data["CVE"]:
                    aliases = vuln.get("aliases", [])
                    for alias in aliases:
                        if alias.startswith("CVE-"):
                            vuln_data["CVE"] = alias
                            break
                
                all_vulns.append(vuln_data)
            
            # Respect rate limits
            time.sleep(0.1)
            
        except Exception as e:
            print(f"   ⚠️  Erro ao processar {pkg}: {e}")
            continue
    
    print(f"\n✅ Total de vulnerabilidades encontradas: {len(all_vulns)}")
    
    # Save to CSV
    if not all_vulns:
        print("⚠️  Nenhuma vulnerabilidade encontrada nos pacotes consultados")
        print("💡 Isso pode significar que:")
        print("   • Os pacotes consultados não têm vulnerabilidades conhecidas")
        print("   • As versões atuais já foram corrigidas")
        # Create empty CSV for consistency
        df = pd.DataFrame(columns=["PROJECT_NAME", "PROJECT_TYPE", "PRODUCT_NAME", "ISSUE_SEVERITY", 
                                   "CVE", "CWE", "SEMVER_VULNERABLE_RANGE", "FIXED_IN_VERSION",
                                   "VULNERABILITY_PUBLICATION_DATE", "FIRST_INTRODUCED", "UPDATED_AT"])
        out_csv = os.path.join(out_dir, "downloads", f"osv_vulns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        df.to_csv(out_csv, index=False)
        return out_csv
    
    df = pd.DataFrame(all_vulns)
    out_csv = os.path.join(out_dir, "downloads", f"osv_vulns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    df.to_csv(out_csv, index=False)
    print(f"✅ Vulnerabilidades salvas em: {out_csv}")
    
    return out_csv

def build_and_analyze(csv_path: str, packages: List[str], start: date, end: date, out_dir="outputs") -> pd.DataFrame:
    print(f"\n📊 Analisando dados do Snyk...")
    df = pd.read_csv(csv_path)
    df["__package"] = df.get("PROJECT_NAME") if "PROJECT_NAME" in df.columns else df.get("package", df.get("name"))
    df["__package"] = df["__package"].astype(str).apply(canonicalize_name)
    df = df[df["__package"].isin(set(packages))].copy().reset_index(drop=True)
    print(f"   Encontradas {len(df)} vulnerabilidades nos pacotes selecionados")

    rows = []; cache_releases: Dict[str, Dict[str, date]] = {}
    total_rows = len(df)
    print(f"\n🔄 Processando {total_rows} vulnerabilidades...")
    for idx, r in df.iterrows():
        if idx % 10 == 0:
            print(f"   Processado: {idx}/{total_rows} ({100*idx//total_rows}%)")
        row = r.to_dict(); pkg = row["__package"]
        disclosed = pdate(row.get("VULNERABILITY_PUBLICATION_DATE") or row.get("published") or row.get("disclosed"))
        fix_ver = parse_fixed_version(row)
        first_aff_ver = estimate_first_affected_version(row)
        cwes = extract_cwes(row)
        if pkg not in cache_releases:
            print(f"   📥 Buscando releases do pacote: {pkg}")
            cache_releases[pkg] = get_pypi_release_dates(pkg)
        rel_dates = cache_releases[pkg]
        first_aff_date = rel_dates.get(first_aff_ver) if first_aff_ver else None
        mitigation_date = rel_dates.get(fix_ver) if fix_ver else None

        in_window = ((disclosed is not None and start <= disclosed <= end) or
                     (mitigation_date is not None and start <= mitigation_date <= end))
        if not in_window: continue

        disclosure_lag = (disclosed - first_aff_date).days if (disclosed and first_aff_date) else None
        ttf_from_first = (mitigation_date - first_aff_date).days if (mitigation_date and first_aff_date) else None
        ttf_from_disc = (mitigation_date - disclosed).days if (mitigation_date and disclosed) else None
        bump = semver_bump(first_aff_ver, fix_ver)

        rows.append({
            "package": pkg,
            "cve": row.get("CVE"),
            "cwes": ";".join(cwes) if cwes else None,
            "severity": row.get("ISSUE_SEVERITY") or row.get("severity"),
            "first_affected_version": first_aff_ver,
            "first_affected_date": first_aff_date,
            "disclosed_date": disclosed,
            "mitigation_version": fix_ver,
            "mitigation_date": mitigation_date,
            "disclosure_lag_days": disclosure_lag,
            "time_to_fix_from_first_days": ttf_from_first,
            "time_to_fix_from_disclosure_days": ttf_from_disc,
            "fix_semver_type": bump,
        })

    out = pd.DataFrame(rows)
    out_csv = os.path.join(out_dir, f"top_pypi_snyk_timeline_{start.strftime('%Y%m%d')}_{end.strftime('%Y%m%d')}.csv")
    out.to_csv(out_csv, index=False)
    print(f"\n✅ Timeline CSV salvo: {out_csv}")
    print(f"   Total de vulnerabilidades processadas: {len(out)}")

    # summaries
    print(f"\n📈 Gerando estatísticas e gráficos...")
    summaries_dir = os.path.join(out_dir, "summaries"); plots_dir = os.path.join(out_dir, "plots")
    
    if len(out) == 0:
        print("⚠️  Nenhuma vulnerabilidade para analisar. Pulando gráficos.")
        return out, out_csv
    
    tmp = out.copy()
    # Accept both 'cwes' and 'CWE' column names
    cwe_col = "cwes" if "cwes" in tmp.columns else ("CWE" if "CWE" in tmp.columns else None)
    if cwe_col:
        tmp["cwe_list"] = tmp[cwe_col].fillna("").apply(lambda s: [x for x in str(s).split(";") if x])
    else:
        tmp["cwe_list"] = [[] for _ in range(len(tmp))]
    cwe_counts = tmp.explode("cwe_list").groupby("cwe_list", dropna=False).size().reset_index(name="count").sort_values("count", ascending=False)
    cwe_counts.to_csv(os.path.join(summaries_dir, "cwe_counts.csv"), index=False)

    def describe_series(s: pd.Series) -> pd.DataFrame:
        s = pd.to_numeric(s, errors="coerce").dropna()
        return pd.DataFrame({"count":[int(s.count())],
                             "median":[float(s.median()) if not s.empty else float("nan")],
                             "p90":[float(s.quantile(0.90)) if not s.empty else float("nan")],
                             "min":[float(s.min()) if not s.empty else float("nan")],
                             "max":[float(s.max()) if not s.empty else float("nan")],})
    describe_series(out["time_to_fix_from_first_days"]).to_csv(os.path.join(summaries_dir, "ttf_first_stats.csv"), index=False)
    describe_series(out["time_to_fix_from_disclosure_days"]).to_csv(os.path.join(summaries_dir, "ttf_disc_stats.csv"), index=False)

    # boxplot by severity
    def boxplot_save(series_by_group: Dict[str, pd.Series], title: str, outpath: str, ylabel: str):
        fig = plt.figure()
        data = [pd.to_numeric(s, errors="coerce").dropna().values for s in series_by_group.values()]
        labels = list(series_by_group.keys())
        plt.boxplot(data, labels=labels, showfliers=False)
        plt.title(title); plt.ylabel(ylabel); plt.tight_layout(); fig.savefig(outpath, dpi=150); plt.close(fig)
    series_by_sev_first = {str(k): v for k, v in out.groupby("severity")["time_to_fix_from_first_days"]}
    if series_by_sev_first:
        boxplot_save(series_by_sev_first, "Time to Fix (from first affected) by severity", os.path.join(plots_dir, "boxplot_ttf_first_by_severity.png"), "days")

    # KM survival
    out["observed_fix"] = out["mitigation_date"].notna()
    kmf = KaplanMeierFitter()
    for col, label, fname in [
        ("time_to_fix_from_first_days", "KM: time to fix since first affected", "km_since_first.png"),
        ("time_to_fix_from_disclosure_days", "KM: time to fix since disclosure", "km_since_disclosure.png"),
    ]:
        fig = plt.figure()
        durations = pd.to_numeric(out[col], errors="coerce").fillna(0)
        events = out["observed_fix"].fillna(False)
        try:
            kmf.fit(durations=durations, event_observed=events, label=label)
            ax = kmf.plot_survival_function(); ax.set_title(label); ax.set_xlabel("days"); ax.set_ylabel("survival probability")
            fig.tight_layout(); fig.savefig(os.path.join(plots_dir, fname), dpi=150)
        except Exception:
            pass
        plt.close(fig)

    return out, out_csv

def main():
    parser = argparse.ArgumentParser(description="Top PyPI packages → Snyk/OSV Vulnerability Database + CWE + mitigation + survival")
    parser.add_argument("--top-file", help="Local Top PyPI packages JSON/CSV. If omitted, fetch online JSON.", default=None)
    parser.add_argument("--top-limit", type=int, default=5000, help="How many top packages to consider (default 5000).")
    parser.add_argument("--csv", help="Local vulnerability CSV (skip API if provided).", default=None)
    parser.add_argument("--snyk-token", help="Snyk API token")
    parser.add_argument("--snyk-org-id", help="Snyk Organization ID")
    parser.add_argument("--nvd-api-key", help="NVD API key (50 req/30s vs 5 req/30s without key)")
    parser.add_argument("--start", help="Start YYYY-MM-DD (default: today-3y)")
    parser.add_argument("--end", help="End YYYY-MM-DD (default: today)")
    parser.add_argument("--outdir", default="outputs", help="Output directory")
    parser.add_argument("--test-auth", action="store_true", help="Test Snyk authentication")
    parser.add_argument("--use-snyk-export", action="store_true", help="Use Snyk Export API (tem CWE completo, requer token)")
    parser.add_argument("--use-combined", action="store_true", help="Use OSV+NVD combinado (MELHOR: CWE + versões, otimizado)")
    parser.add_argument("--use-nvd", action="store_true", help="Use NVD API (TEM CWE COMPLETO, gratuita, rate limits)")
    parser.add_argument("--use-osv", action="store_true", help="Use OSV API gratuita (sem CWE completo)")
    args = parser.parse_args()

    ensure_dirs(args.outdir)

    today = datetime.utcnow().date()
    start = datetime.strptime(args.start, "%Y-%m-%d").date() if args.start else (today - relativedelta(years=3))
    end = datetime.strptime(args.end, "%Y-%m-%d").date() if args.end else today
    
    # Test authentication if requested
    if args.test_auth:
        if not (args.snyk_token and args.snyk_org_id):
            print("⚠️  Snyk token/org-id não fornecidos.")
            return
        success = test_snyk_auth(args.snyk_token, args.snyk_org_id, use_org=True)
        if success:
            print("\n✅ Autenticação Snyk OK! Pode usar --use-snyk-export")
        else:
            print("\n❌ Autenticação Snyk falhou.")
        return

    packages = fetch_top_packages(args.top_file, limit=args.top_limit)

    if args.csv:
        vuln_csv = args.csv
        print(f"\n📄 Usando arquivo CSV local: {vuln_csv}")
    elif args.use_snyk_export:
        # Use Snyk Export API (completo com CWE, CVE, CVSS, etc.)
        if not (args.snyk_token and args.snyk_org_id):
            raise SystemExit("❌ --use-snyk-export requer --snyk-token e --snyk-org-id")
        
        print("\n" + "=" * 60)
        print("📌 MODO: Snyk Export API (CWE + CVE + CVSS completo)")
        print("=" * 60)
        
        if not test_snyk_auth(args.snyk_token, args.snyk_org_id, use_org=True):
            raise SystemExit("❌ Autenticação falhou.")
        
        vuln_csv = fetch_snyk_vulnerabilities_export(args.snyk_token, args.snyk_org_id, start, end, out_dir=args.outdir)
        
    elif args.use_combined:
        # Use COMBINED OSV + NVD (BEST!)
        print("\n" + "=" * 60)
        print("📌 MODO: COMBINADO OSV+NVD (Otimizado + CWE Completo)")
        print("=" * 60)
        vuln_csv = fetch_combined_vulnerabilities(packages, start, end, nvd_api_key=args.nvd_api_key, out_dir=args.outdir)
        
    elif args.use_nvd:
        # Use NVD API (gratuita COM CWE completo!)
        print("\n" + "=" * 60)
        print("📌 MODO: NVD API (NIST - CWE COMPLETO + CVE + CVSS)")
        print("=" * 60)
        vuln_csv = fetch_nvd_vulnerabilities(packages, start, end, nvd_api_key=args.nvd_api_key, out_dir=args.outdir)
        
    elif args.use_osv:
        # Use OSV API (gratuita mas sem CWE completo)
        print("\n" + "=" * 60)
        print("📌 MODO: OSV API (gratuita, mas CWE pode estar incompleto)")
        print("=" * 60)
        vuln_csv = fetch_snyk_vulnerabilities_for_packages(args.snyk_token, packages, args.snyk_org_id or "none", out_dir=args.outdir)
        
    else:
        # Default: show available options
        if args.snyk_token and args.snyk_org_id:
            print("\n💡 Escolha uma fonte de dados:")
            print("   --use-combined   : OSV+NVD Combinado (RECOMENDADO: CWE + versões, otimizado)")
            print("   --use-snyk-export : Snyk Export API (requer plano pago)")
            print("   --use-nvd        : NVD API (TEM CWE!, gratuita, mais lenta)")
            print("   --use-osv        : OSV API (sem CWE, gratuita, rápida)")
            print("   --csv ARQUIVO    : Usar CSV local")
            raise SystemExit("❌ Especifique uma das opções acima")
        else:
            print("\n💡 Escolha uma fonte de dados:")
            print("   --use-combined : OSV+NVD Combinado (RECOMENDADO: CWE + versões, otimizado)")
            print("   --use-nvd : NVD API (TEM CWE COMPLETO!, gratuita)")
            print("   --use-osv : OSV API (sem CWE, gratuita)")
            print("   --csv ARQUIVO : Usar CSV local")
            raise SystemExit("❌ Especifique uma das opções acima")

    out, out_csv = build_and_analyze(vuln_csv, packages, start, end, out_dir=args.outdir)
    print("\n" + "=" * 60)
    print("✅ ANÁLISE COMPLETA!")
    print("=" * 60)
    print(f"📄 Timeline CSV: {out_csv}")
    print(f"📊 Total de vulnerabilidades: {len(out)}")
    print(f"📁 Gráficos salvos em: {os.path.join(args.outdir, 'plots')}")
    print(f"📈 Estatísticas em: {os.path.join(args.outdir, 'summaries')}")

if __name__ == "__main__":
    main()
