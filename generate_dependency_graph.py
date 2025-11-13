#!/usr/bin/env python3
"""
Gera CSV de dependências entre pacotes Python a partir do PyPI.
Cria o arquivo python_dependencies_edges.csv necessário para análise de rede.
"""

import pandas as pd
import requests
import time
from typing import Set, List, Tuple

def get_package_dependencies(package_name: str) -> Set[str]:
    """
    Busca dependências de um pacote no PyPI API.
    Retorna set de nomes de dependências.
    """
    try:
        url = f"https://pypi.org/pypi/{package_name}/json"
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            return set()
        
        data = response.json()
        
        # Pegar última versão
        info = data.get("info", {})
        requires_dist = info.get("requires_dist", [])
        
        if not requires_dist:
            return set()
        
        # Extrair nomes de dependências (remover versões e extras)
        deps = set()
        for req in requires_dist:
            if not req:
                continue
            
            # Remover especificadores de versão e extras
            dep_name = req.split(';')[0].strip()  # Remove condições
            dep_name = dep_name.split('[')[0].strip()  # Remove extras
            dep_name = dep_name.split('=')[0].strip()  # Remove versões
            dep_name = dep_name.split('>')[0].strip()
            dep_name = dep_name.split('<')[0].strip()
            dep_name = dep_name.split('!')[0].strip()
            dep_name = dep_name.split('~')[0].strip()
            
            if dep_name:
                deps.add(dep_name.lower())
        
        return deps
        
    except Exception as e:
        return set()


def generate_dependency_edges(packages: List[str], output_csv: str = "python_dependencies_edges.csv"):
    """
    Gera CSV de arestas de dependências.
    Formato: source,target
    """
    print(f"🔍 Buscando dependências de {len(packages)} pacotes...")
    print(f"   (Isso pode demorar ~15 minutos)")
    print()
    
    edges = []
    total = len(packages)
    
    for idx, pkg in enumerate(packages, 1):
        if idx % 5 == 0 or idx == 1:
            print(f"   [{idx}/{total}] {pkg}")
        
        deps = get_package_dependencies(pkg)
        
        for dep in deps:
            # Adicionar aresta: pkg depende de dep
            edges.append({
                "source": pkg.lower(),
                "target": dep.lower()
            })
        
        # Rate limiting (PyPI permite ~10 req/s)
        time.sleep(0.15)
    
    print(f"\n✅ Total de arestas encontradas: {len(edges)}")
    
    # Criar DataFrame
    df = pd.DataFrame(edges)
    
    # Remover duplicatas
    df = df.drop_duplicates()
    print(f"✅ Arestas únicas: {len(df)}")
    
    # Salvar
    df.to_csv(output_csv, index=False)
    print(f"💾 Salvo em: {output_csv}")
    
    # Estatísticas
    print(f"\n📊 Estatísticas:")
    print(f"   Pacotes como source: {df['source'].nunique()}")
    print(f"   Pacotes como target: {df['target'].nunique()}")
    print(f"   Top 10 pacotes mais usados:")
    top_deps = df['target'].value_counts().head(10)
    for dep, count in top_deps.items():
        print(f"      {dep}: {count} pacotes")
    
    return df


if __name__ == "__main__":
    # Carregar lista de pacotes
    vuln_csv = "outputs/top_pypi_snyk_timeline_20231101_20251101.csv"
    
    print(f"📂 Carregando pacotes de: {vuln_csv}")
    vulns = pd.read_csv(vuln_csv)
    
    packages = vulns['package'].unique().tolist()
    packages = sorted(set(p.lower() for p in packages if p and str(p) != 'nan'))
    
    print(f"✅ Pacotes únicos encontrados: {len(packages)}")
    print()
    
    # Gerar dependências
    df = generate_dependency_edges(packages, "python_dependencies_edges.csv")
    
    print(f"\n✅ CONCLUÍDO!")
    print(f"   Agora você pode usar 'python_dependencies_edges.csv' no notebook")

