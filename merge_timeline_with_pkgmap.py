#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Merge existing timeline CSV with package_severity_map.csv
---------------------------------------------------------
1) Preenche severity e cwes no timeline usando o package_severity_map.csv
2) Opcional: acrescenta pacotes que só existem no package map
3) Opcional: inclui pacotes dependentes vindos de python_dependencies_edges.csv e
   preenche dados ausentes via OSV (quando habilitado)
"""
import argparse
import os
import pandas as pd
import json
import time
import requests
from datetime import datetime
from packaging.version import Version, InvalidVersion


def main():
    ap = argparse.ArgumentParser(description="Merge timeline with package severity/CWEs map")
    ap.add_argument("--timeline", required=True, help="Path to timeline CSV (from top_pypi_snyk_last3y.py)")
    ap.add_argument("--pkgmap", required=True, help="Path to outputs/summaries/package_severity_map.csv")
    ap.add_argument("--out", default="outputs/summaries/top_pypi_snyk_timeline_merged.csv", help="Output CSV path")
    ap.add_argument("--include-missing", action="store_true", help="Append packages present only in pkgmap")
    ap.add_argument("--edges", default=None, help="Optional: python_dependencies_edges.csv to include dependent packages")
    ap.add_argument("--use-osv", action="store_true", help="If set, query OSV to fill missing severity/CWEs for new packages")
    ap.add_argument("--osv-cap", type=int, default=500, help="Max OSV queries (when --use-osv)")
    ap.add_argument("--osv-sleep", type=float, default=0.15, help="Sleep between OSV requests")
    ap.add_argument("--osv-timeout", type=int, default=20, help="Timeout for OSV requests")
    ap.add_argument("--use-nvd", action="store_true", help="If set, query NVD to enrich packages from pkgmap (severity!=unknown & cwe_count>0)")
    ap.add_argument("--nvd-cap", type=int, default=300, help="Max NVD package queries")
    ap.add_argument("--nvd-sleep", type=float, default=7.0, help="Sleep between NVD requests (public rate limit)")
    ap.add_argument("--nvd-timeout", type=int, default=30, help="Timeout for NVD requests")
    args = ap.parse_args()

    print(f"\n📄 Timeline: {args.timeline}")
    print(f"📄 Package map: {args.pkgmap}")
    print(f"📤 Output: {args.out}")

    tl = pd.read_csv(args.timeline)
    pm = pd.read_csv(args.pkgmap)

    if "package" not in tl.columns:
        raise SystemExit("❌ Timeline must contain column 'package'")
    tl["package"] = tl["package"].astype(str).str.lower()
    pm["package"] = pm["package"].astype(str).str.lower()
    # Ensure cwe_list parsed to list
    if "cwe_list" in pm.columns and pm["cwe_list"].dtype == object:
        def _tolist(x):
            if isinstance(x, list):
                return x
            try:
                v = json.loads(x)
                if isinstance(v, list):
                    return v
            except Exception:
                pass
            return [y for y in str(x).split(";") if y]
        pm["cwe_list"] = pm["cwe_list"].apply(_tolist)

    pkg2sev = dict(zip(pm["package"], pm["severity_max"]))
    pkg2cwe = dict(zip(pm["package"], pm["cwe_list"]))

    def _parse_date(s):
        try:
            return datetime.fromisoformat(str(s).replace("Z",""))
        except Exception:
            return None

    def _semver_bump(a: str, b: str) -> str:
        try:
            if not a or not b:
                return "unknown"
            va, vb = Version(str(a)), Version(str(b))
            if va.major != vb.major:
                return "major"
            if va.minor != vb.minor:
                return "minor"
            if va.micro != vb.micro:
                return "patch"
            return "same"
        except Exception:
            return "unknown"

    # Fetch PyPI release upload dates to compute first_affected_date and mitigation_date
    def _get_pypi_release_dates(package: str) -> dict:
        try:
            r = requests.get(f"https://pypi.org/pypi/{package}/json", timeout=20)
            if r.status_code != 200:
                return {}
            data = r.json()
        except Exception:
            return {}
        out = {}
        for ver, files in (data.get("releases") or {}).items():
            dates = []
            for f in files or []:
                ts = f.get("upload_time_iso_8601") or f.get("upload_time")
                d = _parse_date(ts)
                if d:
                    dates.append(d.date())
            if dates:
                out[ver] = min(dates)
        return out
    _release_dates_cache = {}
    def _first_date_for_version(pkg: str, ver: str):
        if not ver:
            return None
        pkg_l = str(pkg).lower()
        if pkg_l not in _release_dates_cache:
            _release_dates_cache[pkg_l] = _get_pypi_release_dates(pkg_l)
        return _release_dates_cache[pkg_l].get(ver)

    # Ensure severity column exists and fill empties/unknowns
    if "severity" not in tl.columns:
        tl["severity"] = "unknown"
    tl["severity"] = tl["severity"].astype(str).str.lower()
    mask_sev = tl["severity"].isin(["", "nan", "none", "unknown"])
    tl.loc[mask_sev, "severity"] = tl.loc[mask_sev, "package"].map(pkg2sev).fillna(tl.loc[mask_sev, "severity"])

    # Ensure CWEs column exists and fill empties
    cwe_col = "cwes" if "cwes" in tl.columns else "CWE" if "CWE" in tl.columns else "cwes"
    if cwe_col not in tl.columns:
        tl[cwe_col] = ""
    tl[cwe_col] = tl[cwe_col].fillna("").astype(str)
    mask_cwe = tl[cwe_col].isin(["", "nan", "none"])
    tl.loc[mask_cwe, cwe_col] = tl.loc[mask_cwe, "package"].map(
        lambda p: ";".join(pm.loc[pm["package"] == p, "cwe_list"].iloc[0]) if p in pkg2cwe else ""
    ).fillna(tl.loc[mask_cwe, cwe_col])

    # Optionally append packages that are only in pkgmap
    if args.include_missing:
        tl_pkgs = set(tl["package"].unique())
        miss = [p for p in pm["package"].tolist() if p not in tl_pkgs]
        if miss:
            print(f"➕ Appending {len(miss)} packages not present in timeline")
            cols = list(tl.columns)
            if cwe_col not in cols:
                cols.append(cwe_col)
            extra = []
            for p in miss:
                row = {c: "" for c in cols}
                row["package"] = p
                row["severity"] = pkg2sev.get(p, "unknown")
                row[cwe_col] = ";".join(pkg2cwe.get(p, []))
                extra.append(row)
            tl = pd.concat([tl, pd.DataFrame(extra)], ignore_index=True)

    # Optional: include dependent packages from edges (and backfill via OSV if asked)
    if args.edges:
        print(f"📄 Edges: {args.edges}")
        import pandas as _pd
        deps = _pd.read_csv(args.edges)
        for col in ("source", "target"):
            if col not in deps.columns:
                raise SystemExit(f"❌ Edges must contain '{col}'")
            deps[col] = deps[col].astype(str).str.lower()
        all_nodes = set(deps["source"]).union(set(deps["target"]))
        tl_pkgs = set(tl["package"].unique())
        pm_pkgs = set(pm["package"].unique())
        new_nodes = sorted(list(all_nodes - tl_pkgs))
        print(f"🔎 Dependent packages not in timeline: {len(new_nodes)}")
        # Prepare OSV backfill if required
        osv_rows = []
        osv_rows_timeline = []  # vulnerability-level rows to append with full timeline columns
        if args.use_osv and new_nodes:
            sess = requests.Session()
            total = min(len(new_nodes), args.osv_cap)
            print(f"🌐 OSV backfill for {total} packages...")
            for idx, p in enumerate(new_nodes[:args.osv_cap], 1):
                print(f"   [{idx}/{total}] OSV: {p}")
                try:
                    r = sess.post("https://api.osv.dev/v1/query",
                                  json={"package": {"name": p, "ecosystem": "PyPI"}},
                                  timeout=args.osv_timeout)
                    if r.status_code != 200:
                        time.sleep(args.osv_sleep); continue
                    data = r.json()
                    vulns = data.get("vulns") or []
                    # derive severity max (low<medium<high<critical) and CWEs
                    sev_rank = {"low":1,"medium":2,"moderate":2,"high":3,"critical":4}
                    inv = {v:k for k,v in sev_rank.items()}
                    max_rank = 0; cwes=set()
                    for v in vulns:
                        sev = None
                        if isinstance(v.get("database_specific"), dict):
                            sev = (v["database_specific"].get("severity") or "").lower() or None
                        if not sev:
                            for s in v.get("severity", []) or []:
                                if s.get("type")=="CVSS_V3":
                                    score = s.get("score")
                                    if score:
                                        try:
                                            import re as _re
                                            m=_re.search(r"(\\d+\\.\\d+)", str(score))
                                            sc=float(m.group(1)) if m else float(score)
                                            sev="critical" if sc>=9 else "high" if sc>=7 else "medium" if sc>=4 else "low"
                                        except Exception:
                                            pass
                                    break
                        rnk = sev_rank.get(sev or "low",0); 
                        if rnk>max_rank: max_rank=rnk
                        # CWEs anywhere
                        def walk(x):
                            if isinstance(x, dict):
                                for k,v in x.items(): walk(k); walk(v)
                            elif isinstance(x, (list,tuple)):
                                for it in x: walk(it)
                            else:
                                try:
                                    s=str(x)
                                    import re as _re
                                    for m in _re.findall(r"CWE-\\d+", s, flags=_re.IGNORECASE):
                                        cwes.add(m.upper())
                                except Exception: pass
                        walk(v)
                        # Build timeline-like row for this vulnerability
                        cve_id = v.get("id") if str(v.get("id","")).startswith("CVE-") else ""
                        if not cve_id:
                            for alias in v.get("aliases", []) or []:
                                if str(alias).startswith("CVE-"):
                                    cve_id = alias; break
                        # introduced/fixed from ECOSYSTEM ranges
                        introduced = None; fixed = None
                        for aff in v.get("affected", []) or []:
                            if aff.get("package", {}).get("name")==p:
                                for rng in aff.get("ranges", []) or []:
                                    if rng.get("type")=="ECOSYSTEM":
                                        for ev in rng.get("events", []) or []:
                                            if "introduced" in ev and not introduced:
                                                introduced = ev["introduced"]
                                            if "fixed" in ev and not fixed:
                                                fixed = ev["fixed"]
                        published = v.get("published")
                        osv_rows_timeline.append({
                            "package": p,
                            "cve": cve_id,
                            "cwes": ";".join(sorted(cwes)),
                            "severity": inv.get(max_rank, "unknown"),
                            "first_affected_version": introduced or "",
                            "first_affected_date": "",
                            "disclosed_date": published or "",
                            "mitigation_version": fixed or "",
                            "mitigation_date": "",
                            "disclosure_lag_days": "",
                            "time_to_fix_from_first_days": "",
                            "time_to_fix_from_disclosure_days": "",
                            "fix_semver_type": ""
                        })
                    osv_rows.append({"package": p, "severity_max": inv.get(max_rank,"unknown"),
                                     "cwe_list": sorted(cwes)})
                except Exception:
                    pass
                time.sleep(args.osv_sleep)
            if osv_rows:
                bf = pd.DataFrame(osv_rows)
                # Extend pkg map dicts with backfilled values (only if not already present)
                for _,r in bf.iterrows():
                    if r["package"] not in pkg2sev or pkg2sev[r["package"]]=="unknown":
                        pkg2sev[r["package"]] = r["severity_max"]
                    if r["package"] not in pkg2cwe or not pkg2cwe[r["package"]]:
                        pkg2cwe[r["package"]] = r["cwe_list"]
        # Append all new nodes to timeline with best-known sev/cwes
        if new_nodes:
            cols = list(tl.columns)
            if cwe_col not in cols:
                cols.append(cwe_col)
            extras=[]
            for p in new_nodes:
                row = {c:"" for c in cols}
                row["package"]=p
                row["severity"]=pkg2sev.get(p,"unknown")
                row[cwe_col]=";".join(pkg2cwe.get(p,[])) if isinstance(pkg2cwe.get(p,[]), list) else str(pkg2cwe.get(p,""))
                extras.append(row)
            tl = pd.concat([tl, pd.DataFrame(extras)], ignore_index=True)
            # If we built vulnerability-level rows from OSV, prefer those instead of blank rows
            if args.use_osv and osv_rows_timeline:
                tl = pd.concat([tl, pd.DataFrame(osv_rows_timeline)], ignore_index=True)

    # OSV enrichment for packages from pkgmap: severity != unknown AND cwe_count > 0
    if args.use_osv:
        if "cwe_count" in pm.columns:
            target_pm = pm[(pm["severity_max"].astype(str).str.lower() != "unknown") & (pm["cwe_count"].fillna(0).astype(int) > 0)]
        else:
            target_pm = pm[(pm["severity_max"].astype(str).str.lower() != "unknown")]
        target_packages = sorted(target_pm["package"].unique().tolist())
        if target_packages:
            print(f"🌐 OSV enrichment for {len(target_packages)} packages from pkgmap (non-unknown, cwe_count>0)")
            sess = requests.Session()
            # Build index of existing rows by (package, cve)
            key_to_idx = {}
            if "cve" in tl.columns:
                for i, (p,c) in enumerate(zip(tl["package"].astype(str).str.lower(), tl["cve"].astype(str))):
                    key_to_idx[(p, c)] = i
            # Ensure all timeline columns exist
            needed_cols = ["package","cve","cwes","severity","first_affected_version","first_affected_date",
                           "disclosed_date","mitigation_version","mitigation_date","disclosure_lag_days",
                           "time_to_fix_from_first_days","time_to_fix_from_disclosure_days","fix_semver_type"]
            for col in needed_cols:
                if col not in tl.columns:
                    tl[col] = ""
            appended_rows = []
            total = min(len(target_packages), max(args.osv_cap, 0) if args.osv_cap else len(target_packages))
            for idx, p in enumerate(target_packages[:total], 1):
                print(f"   [{idx}/{total}] OSV enrich: {p}")
                try:
                    r = sess.post("https://api.osv.dev/v1/query",
                                  json={"package": {"name": p, "ecosystem": "PyPI"}},
                                  timeout=args.osv_timeout)
                    if r.status_code != 200:
                        time.sleep(args.osv_sleep); continue
                    data = r.json()
                    vulns = data.get("vulns") or []
                    for v in vulns:
                        # severity rank for this vuln
                        sev_rank = {"low":1,"medium":2,"moderate":2,"high":3,"critical":4}
                        inv = {vv:kk for kk,vv in sev_rank.items()}
                        sname = None
                        if isinstance(v.get("database_specific"), dict):
                            sname = (v["database_specific"].get("severity") or "").lower() or None
                        if not sname:
                            for s in v.get("severity", []) or []:
                                if s.get("type")=="CVSS_V3":
                                    score = s.get("score")
                                    if score:
                                        try:
                                            import re as _re
                                            m=_re.search(r"(\\d+\\.\\d+)", str(score))
                                            sc=float(m.group(1)) if m else float(score)
                                            sname="critical" if sc>=9 else "high" if sc>=7 else "medium" if sc>=4 else "low"
                                        except Exception:
                                            pass
                                    break
                        if not sname:
                            sname = "unknown"
                        # CWEs
                        cwes=set()
                        def walk(x):
                            if isinstance(x, dict):
                                for k,vv in x.items(): walk(k); walk(vv)
                            elif isinstance(x, (list,tuple)):
                                for it in x: walk(it)
                            else:
                                try:
                                    s=str(x)
                                    import re as _re
                                    for m in _re.findall(r"CWE-\\d+", s, flags=_re.IGNORECASE):
                                        cwes.add(m.upper())
                                except Exception: pass
                        walk(v)
                        # CVE
                        cve_id = v.get("id") if str(v.get("id","")).startswith("CVE-") else ""
                        if not cve_id:
                            for alias in v.get("aliases", []) or []:
                                if str(alias).startswith("CVE-"):
                                    cve_id = alias; break
                        # Versions from ECOSYSTEM ranges
                        introduced = None; fixed = None
                        for aff in v.get("affected", []) or []:
                            if aff.get("package", {}).get("name")==p:
                                for rng in aff.get("ranges", []) or []:
                                    if rng.get("type")=="ECOSYSTEM":
                                        for ev in rng.get("events", []) or []:
                                            if "introduced" in ev and not introduced:
                                                introduced = ev["introduced"]
                                            if "fixed" in ev and not fixed:
                                                fixed = ev["fixed"]
                        published = v.get("published") or ""
                        # Compute dates from PyPI
                        first_aff_date = _first_date_for_version(p, introduced) if introduced else None
                        mitigation_date = _first_date_for_version(p, fixed) if fixed else None
                        fix_type = _semver_bump(introduced, fixed)
                        disc_dt = _parse_date(published).date() if published else None
                        lag = (disc_dt - first_aff_date).days if (disc_dt and first_aff_date) else ""
                        ttf_first = (mitigation_date - first_aff_date).days if (mitigation_date and first_aff_date) else ""
                        ttf_disc = (mitigation_date - disc_dt).days if (mitigation_date and disc_dt) else ""
                        row = {
                            "package": p,
                            "cve": cve_id,
                            "cwes": ";".join(sorted(cwes)),
                            "severity": sname,
                            "first_affected_version": introduced or "",
                            "first_affected_date": first_aff_date.isoformat() if first_aff_date else "",
                            "disclosed_date": published,
                            "mitigation_version": fixed or "",
                            "mitigation_date": mitigation_date.isoformat() if mitigation_date else "",
                            "disclosure_lag_days": lag,
                            "time_to_fix_from_first_days": ttf_first,
                            "time_to_fix_from_disclosure_days": ttf_disc,
                            "fix_semver_type": fix_type
                        }
                        key = (p, cve_id)
                        if cve_id and key in key_to_idx:
                            i = key_to_idx[key]
                            # Update only empty/unknown fields
                            for kf, val in row.items():
                                if str(tl.at[i, kf]).strip() in ("", "unknown", "nan", "None"):
                                    tl.at[i, kf] = val
                            # Merge CWEs
                            try:
                                prev = str(tl.at[i, "cwes"]).strip()
                                if prev:
                                    merged = sorted(set(prev.split(";")) | set(row["cwes"].split(";")) - set([""]))
                                    tl.at[i, "cwes"] = ";".join(merged)
                                else:
                                    tl.at[i, "cwes"] = row["cwes"]
                            except Exception:
                                tl.at[i, "cwes"] = row["cwes"]
                        else:
                            appended_rows.append(row)
                except Exception:
                    pass
                time.sleep(args.osv_sleep)
            if appended_rows:
                tl = pd.concat([tl, pd.DataFrame(appended_rows)], ignore_index=True)

    # NVD enrichment for pkgmap packages (severity_max != unknown and cwe_count > 0)
    if args.use_nvd:
        if "cwe_count" in pm.columns:
            target_pm = pm[(pm["severity_max"].astype(str).str.lower() != "unknown") & (pm["cwe_count"].fillna(0).astype(int) > 0)]
        else:
            target_pm = pm[(pm["severity_max"].astype(str).str.lower() != "unknown")]
        target_packages = sorted(target_pm["package"].unique().tolist())
        if target_packages:
            print(f"🌐 NVD enrichment for {len(target_packages)} packages from pkgmap (non-unknown, cwe_count>0)")
            sess = requests.Session()
            sess.headers.update({"User-Agent": "PyPI-Vuln-Merge/1.0"})
            # Build index of existing rows by (package, cve)
            key_to_idx = {}
            if "cve" in tl.columns:
                for i, (p,c) in enumerate(zip(tl["package"].astype(str).str.lower(), tl["cve"].astype(str))):
                    key_to_idx[(p, c)] = i
            # Ensure columns exist
            needed_cols = ["package","cve","cwes","severity","first_affected_version","first_affected_date",
                           "disclosed_date","mitigation_version","mitigation_date","disclosure_lag_days",
                           "time_to_fix_from_first_days","time_to_fix_from_disclosure_days","fix_semver_type"]
            for col in needed_cols:
                if col not in tl.columns:
                    tl[col] = ""
            nvd_added = []
            total = min(len(target_packages), max(args.nvd_cap, 0) if args.nvd_cap else len(target_packages))
            for idx_p, pkg in enumerate(target_packages[:total], 1):
                print(f"   [{idx_p}/{total}] NVD: {pkg}")
                try:
                    # Query NVD by keyword (package name)
                    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                    params = {"keywordSearch": f"python {pkg}", "resultsPerPage": 200}
                    r = sess.get(url, params=params, timeout=args.nvd_timeout)
                    if r.status_code == 403:
                        print("      ⚠️  Rate limit; aguardando...")
                        time.sleep(args.nvd_sleep)
                        r = sess.get(url, params=params, timeout=args.nvd_timeout)
                    if r.status_code != 200:
                        print(f"      ⚠️  Status {r.status_code}")
                        time.sleep(args.nvd_sleep)
                        continue
                    data = r.json()
                    vulns = data.get("vulnerabilities", [])
                    for item in vulns:
                        cve = item.get("cve", {})
                        cve_id = cve.get("id") or ""
                        if not cve_id:
                            continue
                        # CWEs
                        cwes = []
                        for weakness in cve.get("weaknesses", []) or []:
                            for desc in weakness.get("description", []):
                                val = desc.get("value")
                                if val and str(val).startswith("CWE-"):
                                    cwes.append(val)
                        cwe_str = ";".join(sorted(set(cwes))) if cwes else ""
                        # Severity via CVSS
                        severity = "unknown"
                        metrics = cve.get("metrics", {})
                        for cvss_version in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                            if metrics.get(cvss_version):
                                cvss_data = (metrics[cvss_version][0] or {}).get("cvssData", {})
                                base = cvss_data.get("baseSeverity", "")
                                if base:
                                    severity = str(base).lower()
                                else:
                                    score = cvss_data.get("baseScore")
                                    if score is not None:
                                        try:
                                            score_f = float(score)
                                            severity = "critical" if score_f>=9 else "high" if score_f>=7 else "medium" if score_f>=4 else "low"
                                        except Exception:
                                            pass
                                break
                        published = cve.get("published") or ""
                        disc_dt = _parse_date(published).date() if published else None
                        # Fill introduced/fixed via OSV-by-CVE, to compute versions and dates
                        introduced = None; fixed = None
                        try:
                            ov = requests.get(f"https://api.osv.dev/v1/vulns/{cve_id}", timeout=20)
                            if ov.status_code == 200:
                                ovj = ov.json()
                                for aff in ovj.get("affected", []) or []:
                                    pkg_obj = aff.get("package", {}) or {}
                                    if str(pkg_obj.get("ecosystem","")).lower()=="pypi" and str(pkg_obj.get("name","")).lower()==pkg:
                                        for rng in aff.get("ranges", []) or []:
                                            if rng.get("type")=="ECOSYSTEM":
                                                for ev in rng.get("events", []) or []:
                                                    if "introduced" in ev and not introduced:
                                                        introduced = ev["introduced"]
                                                    if "fixed" in ev and not fixed:
                                                        fixed = ev["fixed"]
                                        break
                        except Exception:
                            pass
                        first_aff_date = _first_date_for_version(pkg, introduced) if introduced else None
                        mitigation_date = _first_date_for_version(pkg, fixed) if fixed else None
                        fix_type = _semver_bump(introduced, fixed)
                        lag = (disc_dt - first_aff_date).days if (disc_dt and first_aff_date) else ""
                        ttf_first = (mitigation_date - first_aff_date).days if (mitigation_date and first_aff_date) else ""
                        ttf_disc = (mitigation_date - disc_dt).days if (mitigation_date and disc_dt) else ""
                        row = {
                            "package": pkg,
                            "cve": cve_id,
                            "cwes": cwe_str,
                            "severity": severity,
                            "first_affected_version": introduced or "",
                            "first_affected_date": first_aff_date.isoformat() if first_aff_date else "",
                            "disclosed_date": published,
                            "mitigation_version": fixed or "",
                            "mitigation_date": mitigation_date.isoformat() if mitigation_date else "",
                            "disclosure_lag_days": lag,
                            "time_to_fix_from_first_days": ttf_first,
                            "time_to_fix_from_disclosure_days": ttf_disc,
                            "fix_semver_type": fix_type
                        }
                        key = (pkg, cve_id)
                        if cve_id and key in key_to_idx:
                            i = key_to_idx[key]
                            # Update empty/unknown fields and merge CWEs
                            for kf, val in row.items():
                                if str(tl.at[i, kf]).strip() in ("", "unknown", "nan", "None"):
                                    tl.at[i, kf] = val
                            try:
                                prev = str(tl.at[i, "cwes"]).strip()
                                merged = sorted(set([x for x in prev.split(";") if x]) | set([x for x in cwe_str.split(";") if x]))
                                tl.at[i, "cwes"] = ";".join(merged)
                            except Exception:
                                tl.at[i, "cwes"] = cwe_str
                        else:
                            nvd_added.append(row)
                    time.sleep(args.nvd_sleep)
                except Exception:
                    time.sleep(args.nvd_sleep)
                    continue
            if nvd_added:
                tl = pd.concat([tl, pd.DataFrame(nvd_added)], ignore_index=True)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    tl.to_csv(args.out, index=False)
    print(f"✅ Saved: {args.out}")


if __name__ == "__main__":
    main()


