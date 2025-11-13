#!/usr/bin/env python3
"""
Check if you have projects and what API features are available
"""
import requests
import sys

def check_snyk_features(token, org_id):
    sess = requests.Session()
    sess.headers.update({"Authorization": f"token {token}"})
    
    print("=" * 70)
    print("🔍 VERIFICANDO RECURSOS DISPONÍVEIS")
    print("=" * 70)
    
    # Check projects in org
    print("\n📦 Verificando projetos na organização...")
    try:
        v1_url = f"https://api.snyk.io/v1/org/{org_id}/projects"
        r = sess.get(v1_url)
        
        if r.status_code == 200:
            data = r.json()
            projects = data.get("projects", [])
            print(f"✅ Encontrados {len(projects)} projetos")
            
            if projects:
                print("\nPrimeiros 5 projetos:")
                for i, proj in enumerate(projects[:5], 1):
                    print(f"{i}. {proj.get('name', 'N/A')} (Tipo: {proj.get('type', 'N/A')})")
        else:
            print(f"⚠️  Status: {r.status_code}")
            print(f"Resposta: {r.text[:300]}")
    except Exception as e:
        print(f"❌ Erro: {e}")
    
    # Check if export API is available
    print("\n" + "=" * 70)
    print("📤 TESTANDO ACESSO À API DE EXPORT")
    print("=" * 70)
    
    # Try to list available exports
    rest_url = f"https://api.snyk.io/rest/orgs/{org_id}/export"
    print(f"\nTestando: {rest_url}")
    
    try:
        r = sess.get(rest_url, params={"version": "2024-10-15"})
        print(f"Status: {r.status_code}")
        
        if r.status_code == 200:
            print("✅ API de Export está disponível!")
        elif r.status_code == 403:
            print("❌ API de Export NÃO está disponível (403 Forbidden)")
            print("\n💡 Isso geralmente significa:")
            print("   • Seu plano Snyk não inclui a API de Export")
            print("   • Você precisa de um plano Team ou Enterprise")
            print("   • Ou seu token não tem permissões de Admin")
        elif r.status_code == 404:
            print("⚠️  Endpoint não encontrado (404)")
        else:
            print(f"⚠️  Status inesperado: {r.status_code}")
        
        print(f"\nResposta: {r.text[:500]}")
    except Exception as e:
        print(f"❌ Erro: {e}")
    
    # Check issues via v1 API (alternative)
    print("\n" + "=" * 70)
    print("🔍 TESTANDO API ALTERNATIVA (v1 - Issues)")
    print("=" * 70)
    
    try:
        v1_issues_url = f"https://api.snyk.io/v1/org/{org_id}/issues"
        print(f"\nTestando: {v1_issues_url}")
        
        r = sess.post(v1_issues_url, json={"filters": {}})
        print(f"Status: {r.status_code}")
        
        if r.status_code == 200:
            print("✅ API v1 de Issues está disponível!")
            data = r.json()
            print(f"\nResultado: {data.get('ok', False)}")
        else:
            print(f"Resposta: {r.text[:300]}")
    except Exception as e:
        print(f"⚠️  Erro: {e}")
    
    print("\n" + "=" * 70)
    print("📋 RESUMO E RECOMENDAÇÕES")
    print("=" * 70)
    print("""
Se a API de Export retornou 403:
  → Seu plano Snyk Free não tem acesso à API de Export
  → Você precisa upgrade para Team ou Enterprise
  → Alternativa: Use a interface web do Snyk para exportar dados manualmente

Se você já exportou dados manualmente:
  → Salve o arquivo CSV em: outputs/downloads/
  → Execute com: python3.10 top_pypi_snyk_last3y.py --csv outputs/downloads/SEU_ARQUIVO.csv

Mais informações:
  → https://docs.snyk.io/snyk-api-info/snyk-api
  → https://snyk.io/plans/
""")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python3.10 check_snyk_projects.py TOKEN ORG_ID")
        sys.exit(1)
    
    token = sys.argv[1]
    org_id = sys.argv[2]
    check_snyk_features(token, org_id)

