import os
import json
import requests
from datetime import datetime
from crewai.tools import tool
from msal import ConfidentialClientApplication
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

# ==========================================
# HERRAMIENTA 1: Solo ir a Azure (Para Friday)
# ==========================================
@tool("Ejecutar Playbook en Defender")
def run_playbook(playbook_filename: str, equipo: str) -> str:
    """Lee un playbook, reemplaza el equipo, lo ejecuta en Defender y guarda el JSON."""
    path = f"playbooks/{playbook_filename}"
    if not os.path.exists(path):
        return f"Error: No se encontró {playbook_filename}."
    
    with open(path, "r", encoding="utf-8") as f:
        query = f.read().replace("<NOMBRE_DEL_EQUIPO>", equipo)

    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")

    if not all([tenant_id, client_id, client_secret]):
        return "ERROR: Faltan credenciales de Azure en el .env"

    try:
        app = ConfidentialClientApplication(
            client_id, authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret
        )
        result = app.acquire_token_for_client(scopes=["https://api.security.microsoft.com/.default"])
        
        if "access_token" not in result:
            return f"Error de autenticación: {result.get('error_description')}"

        headers = {"Authorization": f"Bearer {result['access_token']}", "Content-Type": "application/json"}
        payload = {"Query": query}
        
        response = requests.post("https://api.security.microsoft.com/api/advancedhunting/run", json=payload, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            results = data.get("Results", [])
            
            os.makedirs("data", exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"data/azure_dump_{timestamp}.json"
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
                
            print(f"   [*] Evidencia completa guardada en: {filename}")

            if not results:
                return "No se encontraron resultados en Azure."
                
            resumen = f"Se encontraron {len(results)} eventos. Muestra:\n"
            for r in results[:3]:
                campos = {k: v for k, v in r.items() if isinstance(v, str) and v.strip()}
                muestra = dict(list(campos.items())[:4])
                resumen += f"- {muestra}\n"
            return resumen
        else:
            return f"Error en la consulta: {response.text}"
    except Exception as e:
        return f"Error de conexión: {e}"

# ==========================================
# HERRAMIENTA 2: Solo redactar (Para Friday)
# ==========================================
@tool("Redactar Informe Forense con Ollama")
def write_report_with_ollama(contexto: str, incidente: str) -> str:
    """Pasa el resumen de los logs a Ollama local para que redacte el informe final."""
    print("   -> Enviando datos a Ollama local para redactar el informe...")
    
    if not contexto or "No se encontraron resultados" in str(contexto):
        return f"Análisis de {incidente}: La consulta no devolvió datos, por lo que no hay riesgos que reportar."

    client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
    prompt = f"Eres un analista DFIR. Investigamos: {incidente}. Datos:\n{contexto}\nRedacta un informe breve (máx 3 líneas): 1. Qué pasó, 2. Riesgo, 3. Acción recomendada."
    
    try:
        response = client.chat.completions.create(
            model="qwen2.5:3b",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error al conectar con Ollama: {e}"

# ==========================================
# HERRAMIENTA 3: Todo en uno (Para Edith y Karen)
# ==========================================
@tool("Ejecutar y Analizar Playbook")
def run_and_analyze(playbook_filename: str, equipo: str, incidente: str) -> str:
    """Ejecuta un playbook en Defender, guarda el JSON en data/, y le pide a Ollama que redacte el informe (Sin pasar por CrewAI)."""
    # Reutilizamos la lógica de las dos herramientas anteriores para no duplicar código
    resultado_azure = run_playbook.run(playbook_filename, equipo)
    
    if "Error" in resultado_azure or "No se encontraron" in resultado_azure:
        return f"Análisis de {incidente}: {resultado_azure}"
        
    return write_report_with_ollama.run(resultado_azure, incidente)