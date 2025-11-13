#!/usr/bin/env python3
"""
Helper script to find your Snyk Organization and Group IDs
"""
import requests
import json

SNYK_BASE = "https://api.snyk.io/rest"
SNYK_VER = "2024-10-15"

def test_snyk_credentials(token):
    """Test token and list available orgs/groups"""
    sess = requests.Session()
    sess.headers.update({"Authorization": f"token {token}"})
    
    print("=" * 70)
    print("🔍 TESTANDO SEU TOKEN SNYK")
    print("=" * 70)
    
    # Test if token is valid by trying to get user info
    try:
        # Try the v1 API to get user/org info
        v1_url = "https://api.snyk.io/v1/user/me"
        r = sess.get(v1_url)
        
        if r.status_code == 200:
            print("\n✅ Token válido!")
            data = r.json()
            print(f"\n👤 Usuário: {data.get('username', 'N/A')}")
            print(f"📧 Email: {data.get('email', 'N/A')}")
        else:
            print(f"\n❌ Token inválido (Status: {r.status_code})")
            print(f"Resposta: {r.text[:200]}")
            return False
            
    except Exception as e:
        print(f"\n❌ Erro ao validar token: {e}")
        return False
    
    # List organizations
    print("\n" + "=" * 70)
    print("📋 LISTANDO SUAS ORGANIZAÇÕES")
    print("=" * 70)
    
    try:
        # Try REST API v3 for orgs
        orgs_url = f"{SNYK_BASE}/orgs"
        r = sess.get(orgs_url, params={"version": SNYK_VER, "limit": 100})
        
        if r.status_code == 200:
            data = r.json()
            orgs = data.get("data", [])
            
            if orgs:
                print(f"\n✅ Encontradas {len(orgs)} organizações:\n")
                for i, org in enumerate(orgs, 1):
                    org_id = org.get("id")
                    org_name = org.get("attributes", {}).get("name", "N/A")
                    print(f"{i}. Nome: {org_name}")
                    print(f"   ID: {org_id}")
                    print()
            else:
                print("\n⚠️  Nenhuma organização encontrada")
        else:
            print(f"\n⚠️  Não foi possível listar organizações (Status: {r.status_code})")
            print(f"Resposta: {r.text[:200]}")
            
    except Exception as e:
        print(f"\n⚠️  Erro ao listar organizações: {e}")
    
    # Try v1 API for orgs as fallback
    try:
        v1_orgs_url = "https://api.snyk.io/v1/orgs"
        r = sess.get(v1_orgs_url)
        
        if r.status_code == 200:
            data = r.json()
            orgs = data.get("orgs", [])
            
            if orgs:
                print("\n" + "=" * 70)
                print("📋 ORGANIZAÇÕES (via API v1)")
                print("=" * 70)
                print(f"\n✅ Encontradas {len(orgs)} organizações:\n")
                for i, org in enumerate(orgs, 1):
                    org_id = org.get("id")
                    org_name = org.get("name", "N/A")
                    print(f"{i}. Nome: {org_name}")
                    print(f"   ID: {org_id}")
                    print()
                    
    except Exception as e:
        pass
    
    # List groups
    print("=" * 70)
    print("📋 LISTANDO SEUS GRUPOS")
    print("=" * 70)
    
    try:
        groups_url = f"{SNYK_BASE}/groups"
        r = sess.get(groups_url, params={"version": SNYK_VER, "limit": 100})
        
        if r.status_code == 200:
            data = r.json()
            groups = data.get("data", [])
            
            if groups:
                print(f"\n✅ Encontrados {len(groups)} grupos:\n")
                for i, group in enumerate(groups, 1):
                    group_id = group.get("id")
                    group_name = group.get("attributes", {}).get("name", "N/A")
                    print(f"{i}. Nome: {group_name}")
                    print(f"   ID: {group_id}")
                    print()
            else:
                print("\n⚠️  Nenhum grupo encontrado")
        else:
            print(f"\n⚠️  Não foi possível listar grupos (Status: {r.status_code})")
            
    except Exception as e:
        print(f"\n⚠️  Erro ao listar grupos: {e}")
    
    print("\n" + "=" * 70)
    print("💡 PRÓXIMOS PASSOS")
    print("=" * 70)
    print("""
Use um dos IDs acima no seu comando:

Para usar Organization ID:
    python3.10 top_pypi_snyk_last3y.py --snyk-token SEU_TOKEN --snyk-org-id ORG_ID_AQUI --test-auth

Para usar Group ID:
    python3.10 top_pypi_snyk_last3y.py --snyk-token SEU_TOKEN --snyk-group-id GROUP_ID_AQUI --test-auth
""")
    
    return True

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python3.10 test_snyk_credentials.py SEU_TOKEN")
        sys.exit(1)
    
    token = sys.argv[1]
    test_snyk_credentials(token)

