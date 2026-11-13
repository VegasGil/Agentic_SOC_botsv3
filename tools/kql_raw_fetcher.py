import os
import json
import requests
from crewai.tools import tool
from msal import ConfidentialClientApplication
from dotenv import load_dotenv

load_dotenv()

@tool("Buscar CVEs en Defender (Raw)")
def fetch_cves_raw(equipo: str) -> str:
    """Busca CVEs en Azure Defender y devuelve el JSON crudo (sin Ollama)."""
    
    # MODO DEMO PARA RECLUTADORES
    if os.getenv("AZURE_TENANT_ID") == "demo":
        print("   -> [DEMO MODE] Simulando búsqueda de CVEs en Defender...")
        return json.dumps([
            {"CveId": "CVE-2021-44228", "SoftwareName": "log4j", "VulnerabilitySeverityLevel": "Critical"},
            {"CveId": "CVE-2024-1234", "SoftwareName": "libpcre2", "VulnerabilitySeverityLevel": "High"}
        ])

    print(f"   -> [Azure] Buscando CVEs para {equipo}...")
    
    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")

    if not all([tenant_id, client_id, client_secret]):
        return "ERROR: Faltan credenciales de Azure."

    try:
        app = ConfidentialClientApplication(
            client_id, authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret
        )
        result = app.acquire_token_for_client(scopes=["https://api.security.microsoft.com/.default"])
        
        if "access_token" not in result:
            return f"Error de autenticación: {result.get('error_description')}"

        # Consulta KQL directamente
        query = f"""
        DeviceTvmSoftwareVulnerabilities
        | where DeviceName has "{equipo}"
        | where VulnerabilitySeverityLevel in ("Critical", "High", "Medium")
        | project CveId, SoftwareName, VulnerabilitySeverityLevel
        | take 10
        """
        
        headers = {"Authorization": f"Bearer {result['access_token']}", "Content-Type": "application/json"}
        payload = {"Query": query}
        
        response = requests.post("https://api.security.microsoft.com/api/advancedhunting/run", json=payload, headers=headers)
        
        if response.status_code != 200:
            return f"Error en Azure: {response.text}"

        results = response.json().get("Results", [])
        return json.dumps(results)
    except Exception as e:
        return f"Error de conexión: {e}"