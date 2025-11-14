#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enrich dependency graph with severity and CWEs using Timeline CSV + OSV backfill
-----------------------------------------------------------------------------
Reads python_dependencies_edges.csv and a vulnerability timeline CSV (produced by
top_pypi_snyk_last3y.py). Builds a package -> {severity_max, cwe_list} map.
For packages missing in the timeline, queries the OSV API to fill severity/CWEs.
Outputs enriched nodes and edges CSVs ready for plotting/analysis.
"""
import argparse
import json
import os
import re
import time
from typing import Dict, List, Set

import networkx as nx
import pandas as pd
import requests


def print_header(args: argparse.Namespace):
    print("\n" + "=" * 70)
    print("📌 MODE: Enrich dependencies with Timeline + OSV backfill (+ optional NVD CWE)")
    print("=" * 70)
    print(f"• Edges CSV          : {args.edges}")
    print(f"• Timeline CSV       : {args.timeline}")
    print(f"• Output directory   : {args.outdir}")
    print(f"• OSV CAP (max pkgs) : {args.cap}")
    print(f"• OSV sleep (seconds): {args.sleep}")
    print(f"• Timeout (seconds)  : {args.timeout}")
    if getattr(args, "use_nvd", False):
        print(f"• NVD enrichment     : ON (API key={'yes' if args.nvd_api_key else 'no'})")
    print("=" * 70)


def normalize_pkg(name: str) -> str:
    return ("" if name is None else str(name)).strip().lower()


def load_edges(path: str) -> pd.DataFrame:
    print(f"\n🔗 Loading dependency edges: {path}")
    edges = pd.read_csv(path)
    for col in ["source", "target"]:
        if col not in edges.columns:
            raise RuntimeError(f"Missing column '{col}' in {path}")
        edges[col] = edges[col].astype(str).str.lower()
    print(f"   ✅ {len(edges)} edges")
    return edges


def build_graph(edges: pd.DataFrame) -> nx.DiGraph:
    G = nx.DiGraph()
    G.add_edges_from(edges[["source", "target"]].itertuples(index=False, name=None))
    print(f"   📦 Graph nodes={G.number_of_nodes()} edges={G.number_of_edges()}")
    return G


def build_map_from_timeline(timeline_csv: str) -> pd.DataFrame:
    print(f"\n🗂️  Loading timeline: {timeline_csv}")
    if not os.path.exists(timeline_csv):
        print(f"   ⚠️  Not found: {timeline_csv}. Proceeding without timeline map.")
        return pd.DataFrame(columns=["package", "severity_max", "cwe_list", "cwe_count"])

    v = pd.read_csv(timeline_csv)
    if "package" not in v.columns:
        raise RuntimeError("Timeline CSV must include a 'package' column.")
    v["package"] = v["package"].astype(str).str.lower()
    v["severity"] = v.get("severity", pd.Series(["unknown"] * len(v))).astype(str).str.lower()
    v["severity"] = v["severity"].replace({"moderate": "medium"})

    sev_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    v["sev_rank"] = v["severity"].map(lambda s: sev_rank.get(s, 0))
    print("   🔢 Computing max severity by package...")
    sev_map = v.groupby("package", as_index=False)["sev_rank"].max()
    inv = {v: k for k, v in sev_rank.items()}
    sev_map["severity_max"] = sev_map["sev_rank"].map(lambda r: inv.get(r, "unknown"))

    if "cwes" in v.columns:
        v["cwe_list"] = v["cwes"].fillna("").map(lambda s: [x for x in str(s).split(";") if x])
    else:
        v["cwe_list"] = [[] for _ in range(len(v))]
    print("   🧮 Aggregating CWE list per package...")
    cwe_map = (
        v.groupby("package")["cwe_list"]
        .apply(lambda lists: sorted({c for lst in lists for c in lst}))
        .reset_index()
    )

    pkg_info = pd.merge(sev_map[["package", "severity_max"]], cwe_map, on="package", how="outer")
    # Normalize nulls without using list in fillna (pandas doesn't accept list scalars there)
    pkg_info["severity_max"] = pkg_info["severity_max"].fillna("unknown")
    # Ensure cwe_list is always a list
    pkg_info["cwe_list"] = pkg_info["cwe_list"].apply(lambda x: x if isinstance(x, list) else ([] if pd.isna(x) else ([y for y in str(x).split(";") if y])))
    pkg_info["cwe_count"] = pkg_info["cwe_list"].apply(len)
    print(f"   ✅ Packages in timeline map: {len(pkg_info)}")
    return pkg_info


_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def extract_cwes_from_obj(obj) -> List[str]:
    found: Set[str] = set()

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                walk(k)
                walk(v)
        elif isinstance(x, (list, tuple)):
            for it in x:
                walk(it)
        else:
            try:
                s = str(x)
                for m in _CWE_RE.findall(s):
                    found.add(m.upper())
            except Exception:
                pass

    walk(obj)
    return sorted(found)


def backfill_with_osv(packages: List[str], cap: int, sleep: float, timeout: int) -> pd.DataFrame:
    print(f"\n🌐 Backfilling missing packages using OSV (cap={cap})...")
    sess = requests.Session()
    sev_rank = {"low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}
    inv_rank = {v: k for k, v in sev_rank.items()}

    result_rows = []
    total = min(len(packages), cap)
    for idx, pkg in enumerate(packages[:cap], 1):
        print(f"   [{idx}/{total}] OSV: {pkg}")
        try:
            r = sess.post(
                "https://api.osv.dev/v1/query",
                json={"package": {"name": pkg, "ecosystem": "PyPI"}},
                timeout=timeout,
            )
        except Exception as e:
            print(f"      ⚠️  Request error: {e}")
            time.sleep(sleep)
            continue

        if r.status_code != 200:
            print(f"      ⚠️  Status {r.status_code}")
            time.sleep(sleep)
            continue

        data = r.json()
        vulns = data.get("vulns") or []
        max_rank = 0
        all_cwes: Set[str] = set()

        for v in vulns:
            sev = None
            dbs = v.get("database_specific")
            if isinstance(dbs, dict):
                sev = (dbs.get("severity") or "").lower() or None
            if not sev:
                for s in v.get("severity", []) or []:
                    if s.get("type") == "CVSS_V3":
                        score = s.get("score")
                        if score:
                            try:
                                m = re.search(r"(\d+\.\d+)", str(score))
                                sc = float(m.group(1)) if m else float(score)
                                sev = "critical" if sc >= 9.0 else "high" if sc >= 7.0 else "medium" if sc >= 4.0 else "low"
                            except Exception:
                                pass
                        break
            rnk = sev_rank.get(sev or "low", 0)
            if rnk > max_rank:
                max_rank = rnk
            all_cwes.update(extract_cwes_from_obj(v))

        print(
            f"      ✅ severity={inv_rank.get(max_rank, 'unknown')} | CWEs={len(all_cwes)}"
        )
        result_rows.append(
            {
                "package": pkg,
                "severity_max": inv_rank.get(max_rank, "unknown"),
                "cwe_list": sorted(all_cwes),
                "cwe_count": len(all_cwes),
            }
        )
        time.sleep(sleep)

    print(f"   🧩 OSV backfilled packages: {len(result_rows)}")
    return pd.DataFrame(result_rows)


def enrich_cwes_with_nvd(packages: List[str], sleep: float, timeout: int, api_key: str | None) -> pd.DataFrame:
    """
    Optional CWE enrichment using NVD. Uses keyword search 'python <pkg>' and
    aggregates CWEs found in weaknesses.
    """
    if not packages:
        return pd.DataFrame(columns=["package", "nvd_cwe_list", "nvd_cwe_count"])
    print(f"\n🏛️  Enriching CWEs from NVD for {len(packages)} packages...")
    sess = requests.Session()
    sess.headers.update({"User-Agent": "PyPI-Vulnerability-Research/1.0"})
    rows = []
    for idx, pkg in enumerate(packages, 1):
        print(f"   [{idx}/{len(packages)}] NVD: {pkg}")
        try:
            params = {"keywordSearch": f"python {pkg}", "resultsPerPage": 200}
            if api_key:
                params["apiKey"] = api_key
            r = sess.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, timeout=timeout)
            if r.status_code != 200:
                print(f"      ⚠️  Status {r.status_code}")
                time.sleep(sleep)
                continue
            data = r.json()
            vulns = data.get("vulnerabilities") or []
            cwes: Set[str] = set()
            for item in vulns:
                cve = item.get("cve", {})
                for weakness in cve.get("weaknesses", []) or []:
                    for desc in weakness.get("description", []) or []:
                        val = desc.get("value")
                        if val and str(val).startswith("CWE-"):
                            cwes.add(str(val))
            rows.append({"package": pkg, "nvd_cwe_list": sorted(cwes), "nvd_cwe_count": len(cwes)})
        except Exception as e:
            print(f"      ⚠️  Error: {e}")
        time.sleep(sleep)
    print(f"   🧩 NVD enriched packages (>=1 CWE): {sum(1 for r in rows if r['nvd_cwe_count']>0)}")
    return pd.DataFrame(rows)


def merge_maps(base: pd.DataFrame, backfill: pd.DataFrame) -> pd.DataFrame:
    print("\n🧷 Merging timeline map with OSV backfill...")
    base = base.copy()
    backfill = backfill.copy()
    if base.empty and backfill.empty:
        return pd.DataFrame(columns=["package", "severity_max", "cwe_list", "cwe_count"])

    sev_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": 0}

    merged = pd.concat([base[["package", "severity_max", "cwe_list", "cwe_count"]], backfill], ignore_index=True)
    merged["rank"] = merged["severity_max"].map(lambda s: sev_rank.get(str(s).lower(), 0))
    merged = (
        merged.sort_values(["package", "rank"], ascending=[True, False])
        .drop_duplicates("package", keep="first")
        .drop(columns=["rank"])
    )
    merged["cwe_count"] = merged["cwe_list"].apply(lambda x: len(x) if isinstance(x, list) else len([y for y in str(x).split(";") if y]))
    print(f"   ✅ Merged packages: {len(merged)}")
    return merged


def write_outputs(edges: pd.DataFrame, pkg_info: pd.DataFrame, outdir: str):
    os.makedirs(outdir, exist_ok=True)
    sev_csv = os.path.join(outdir, "package_severity_map.csv")
    nodes_csv = os.path.join(outdir, "python_dependencies_nodes_enriched.csv")
    edges_csv = os.path.join(outdir, "python_dependencies_edges_enriched.csv")

    print("\n📤 Writing enriched CSVs...")
    pkg_info[["package", "severity_max", "cwe_list", "cwe_count"]].to_csv(sev_csv, index=False)

    G = nx.DiGraph()
    G.add_edges_from(edges[["source", "target"]].itertuples(index=False, name=None))
    indeg = dict(G.in_degree())
    outdeg = dict(G.out_degree())
    nodes = pd.DataFrame({"package": list(G.nodes())})
    nodes["in_degree"] = nodes["package"].map(indeg).fillna(0).astype(int)
    nodes["out_degree"] = nodes["package"].map(outdeg).fillna(0).astype(int)
    pkg2sev: Dict[str, str] = dict(zip(pkg_info["package"], pkg_info["severity_max"]))
    pkg2cwe: Dict[str, List[str]] = dict(zip(pkg_info["package"], pkg_info["cwe_list"]))
    nodes["severity_max"] = nodes["package"].map(pkg2sev).fillna("unknown")
    nodes["cwe_list"] = nodes["package"].map(pkg2cwe).apply(lambda x: x if isinstance(x, list) else [])
    nodes["cwe_count"] = nodes["cwe_list"].apply(len)
    nodes.to_csv(nodes_csv, index=False)

    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": 0}

    def edge_enrich(row: pd.Series) -> pd.Series:
        s, t = row["source"], row["target"]
        ssev, tsev = pkg2sev.get(s, "unknown"), pkg2sev.get(t, "unknown")
        scwe = set(pkg2cwe.get(s, []) or [])
        tcwe = set(pkg2cwe.get(t, []) or [])
        common = sorted(scwe & tcwe)
        return pd.Series(
            {
                "source_severity": ssev,
                "target_severity": tsev,
                "edge_severity_score": max(rank.get(ssev, 0), rank.get(tsev, 0)),
                "shared_cwes": ";".join(common),
                "shared_cwe_count": len(common),
            }
        )

    edges_enriched = edges.copy()
    edges_enriched = pd.concat([edges_enriched, edges_enriched.apply(edge_enrich, axis=1)], axis=1)
    edges_enriched.to_csv(edges_csv, index=False)

    print("   ✅ Saved:")
    print(f"      - {sev_csv}")
    print(f"      - {nodes_csv}")
    print(f"      - {edges_csv}")


def write_timeline_merge(timeline_csv: str, pkg_info: pd.DataFrame, outdir: str, include_missing: bool = False) -> str:
    """
    Create a 'timeline-like' CSV with the same columns as produced by
    top_pypi_snyk_last3y.py, enriching missing severity/CWEs using pkg_info.
    """
    if not os.path.exists(timeline_csv):
        print(f"   ⚠️  Timeline not found, skipping merge: {timeline_csv}")
        return ""
    print("\n🧩 Writing enriched timeline (merge) ...")
    tl = pd.read_csv(timeline_csv)
    if "package" not in tl.columns:
        print("   ⚠️  Timeline missing 'package' column; skipping merge.")
        return ""
    tl["package"] = tl["package"].astype(str).str.lower()
    pkg2sev = dict(zip(pkg_info["package"], pkg_info["severity_max"]))
    pkg2cwe = dict(zip(pkg_info["package"], pkg_info["cwe_list"]))
    # Fill severity if empty/unknown
    if "severity" in tl.columns:
        tl["severity"] = tl["severity"].astype(str).str.lower()
        tl.loc[(tl["severity"].isna()) | (tl["severity"].isin(["", "nan", "none", "unknown"])),
               "severity"] = tl["package"].map(pkg2sev).fillna(tl["severity"])
    else:
        tl["severity"] = tl["package"].map(pkg2sev).fillna("unknown")
    # Fill CWEs if missing
    cwe_col = "cwes" if "cwes" in tl.columns else "CWE" if "CWE" in tl.columns else None
    if cwe_col is None:
        cwe_col = "cwes"
        tl[cwe_col] = ""
    # Normalize existing to string
    tl[cwe_col] = tl[cwe_col].fillna("").astype(str)
    missing_mask = (tl[cwe_col] == "") | (tl[cwe_col].str.lower().isin(["nan", "none"]))
    tl.loc[missing_mask, cwe_col] = tl.loc[missing_mask, "package"].map(
        lambda p: ";".join(pkg2cwe.get(p, []))
    ).fillna(tl.loc[missing_mask, cwe_col])
    # Optionally append packages that exist only in package_severity_map (no timeline rows)
    if include_missing:
        tl_pkgs = set(tl["package"].unique())
        miss_pkgs = [p for p in pkg_info["package"].tolist() if p not in tl_pkgs]
        if miss_pkgs:
            print(f"   ➕ Appending {len(miss_pkgs)} packages missing from timeline...")
            # Build rows with same columns, using severity/cwes from pkg_info and blanks elsewhere
            extra_rows = []
            cols = list(tl.columns)
            cwe_col = "cwes" if "cwes" in tl.columns else "CWE" if "CWE" in tl.columns else "cwes"
            if cwe_col not in cols:
                cols.append(cwe_col)
            for p in miss_pkgs:
                row = {c: "" for c in cols}
                row["package"] = p
                row[cwe_col] = ";".join(pkg2cwe.get(p, []))
                row["severity"] = pkg2sev.get(p, "unknown")
                # keep others empty/NaN-compatible
                extra_rows.append(row)
            tl = pd.concat([tl, pd.DataFrame(extra_rows)], ignore_index=True)

    out_path = os.path.join(outdir, "top_pypi_snyk_timeline_enriched.csv")
    tl.to_csv(out_path, index=False)
    print(f"   ✅ Enriched timeline saved: {out_path}")
    return out_path


def main():
    parser = argparse.ArgumentParser(description="Enrich dependency graph with severity/CWEs using Timeline + OSV backfill")
    parser.add_argument("--edges", default="python_dependencies_edges.csv", help="Path to edges CSV (source,target)")
    parser.add_argument("--timeline", default="outputs/top_pypi_snyk_timeline_20231101_20251101.csv", help="Timeline CSV (from top_pypi_snyk_last3y.py)")
    parser.add_argument("--outdir", default="outputs/summaries", help="Output directory for enriched CSVs")
    parser.add_argument("--cap", type=int, default=500, help="Max number of missing packages to query from OSV")
    parser.add_argument("--sleep", type=float, default=0.15, help="Sleep between OSV requests (seconds)")
    parser.add_argument("--timeout", type=int, default=20, help="HTTP timeout for OSV requests (seconds)")
    parser.add_argument("--use-nvd", action="store_true", help="Also enrich missing CWEs via NVD keyword search")
    parser.add_argument("--nvd-api-key", default=None, help="Optional NVD API key (query param apiKey)")
    parser.add_argument("--write-timeline-merge", action="store_true", help="Also write timeline_enriched.csv with same columns as original timeline, filling missing severity/CWEs")
    parser.add_argument("--include-missing-in-timeline", action="store_true", help="Append packages from severity map that are absent from timeline as blank rows filled with severity/CWEs")
    args = parser.parse_args()

    print_header(args)
    edges = load_edges(args.edges)
    G = build_graph(edges)
    all_nodes = sorted(list(G.nodes()))

    # Timeline mapping
    pkg_info_tl = build_map_from_timeline(args.timeline)
    have = set(pkg_info_tl["package"].tolist()) if not pkg_info_tl.empty else set()
    missing = [p for p in all_nodes if p not in have]
    print(f"\n📊 Packages in graph={len(all_nodes)} | mapped by timeline={len(have)} | missing for OSV={len(missing)}")

    # OSV backfill for missing packages
    pkg_info_osv = backfill_with_osv(missing, cap=args.cap, sleep=args.sleep, timeout=args.timeout)

    # Merge and write outputs
    merged = merge_maps(pkg_info_tl, pkg_info_osv)

    # Optional NVD CWE enrichment for packages still missing CWEs
    if args.use_nvd:
        still_missing_cwe = [p for p, cnt in zip(merged["package"], merged["cwe_count"]) if int(cnt) == 0]
        print(f"\n🔎 Packages missing CWEs after OSV: {len(still_missing_cwe)}")
        if still_missing_cwe:
            nvd_df = enrich_cwes_with_nvd(still_missing_cwe, sleep=args.sleep, timeout=args.timeout, api_key=args.nvd_api_key)
            if not nvd_df.empty:
                pkg2nvd = dict(zip(nvd_df["package"], nvd_df["nvd_cwe_list"]))
                def _add_nvd(row):
                    base_list = row["cwe_list"] if isinstance(row["cwe_list"], list) else []
                    extra = pkg2nvd.get(row["package"], [])
                    merged_list = sorted(set(base_list) | set(extra))
                    row["cwe_list"] = merged_list
                    row["cwe_count"] = len(merged_list)
                    return row
                merged = merged.apply(_add_nvd, axis=1)
    write_outputs(edges, merged, args.outdir)

    if args.write_timeline_merge:
        write_timeline_merge(args.timeline, merged, args.outdir, include_missing=args.include_missing_in_timeline)

    print("\n✅ ENRICHMENT COMPLETE!")


if __name__ == "__main__":
    main()


