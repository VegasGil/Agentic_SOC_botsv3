import os
import json
import requests
from crewai.tools import tool
from dotenv import load_dotenv
from openai import OpenAI

# Importamos librerías de Sigma directamente
from sigma.collection import SigmaCollection
from sigma.backends.kusto import KustoBackend
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline

load_dotenv()

@tool("Cazar Amenazas con Sigma")
def hunt_with_sigma(sigma_file_path: str, equipo: str) -> str:
    """Lee un archivo con múltiples reglas Sigma, las traduce a KQL, las ejecuta y analiza los resultados."""
    print(f"   -> [Hunting] Leyendo reglas Sigma desde: {sigma_file_path}")
    
    if not os.path.exists(sigma_file_path):
        return f"Error: No se encontró el archivo {sigma_file_path}"
        
    with open(sigma_file_path, "r", encoding="utf-8") as f:
        sigma_yaml = f.read()

    # 1. Traducir TODAS las reglas a una lista de consultas KQL
    try:
        rules = SigmaCollection.from_yaml(sigma_yaml)
        backend = KustoBackend(processing_pipeline=microsoft_365_defender_pipeline())
        kql_queries = backend.convert(rules)
    except Exception as e:
        return f"Error traduciendo Sigma: {e}"

    if not kql_queries:
        return "No se generaron consultas KQL a partir del archivo Sigma."

    # 2. Conexión a Azure (hacemos la autenticación una sola vez)
    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")

    try:
        from msal import ConfidentialClientApplication
        app = ConfidentialClientApplication(
            client_id, authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret
        )
        token_result = app.acquire_token_for_client(scopes=["https://api.security.microsoft.com/.default"])
        headers = {"Authorization": f"Bearer {token_result['access_token']}", "Content-Type": "application/json"}
    except Exception as e:
        return f"Error de autenticación en Azure: {e}"

    # 3. Ejecutar cada consulta
    all_results = []
    for i, query in enumerate(kql_queries):
        # Reemplazamos el placeholder del equipo
        query = query.replace("<NOMBRE_DEL_EQUIPO>", equipo)
        print(f"   -> Ejecutando consulta {i+1}/{len(kql_queries)}...")
        
        try:
            response = requests.post(
                "https://api.security.microsoft.com/api/advancedhunting/run", 
                json={"Query": query}, 
                headers=headers
            )
            if response.status_code == 200:
                results = response.json().get("Results", [])
                if results:
                    # Añadimos la consulta a los resultados para saber de dónde vino
                    for r in results:
                        r["_sigma_query"] = query
                    all_results.extend(results)
        except Exception as e:
            print(f"   -> Error en consulta {i+1}: {e}")

    # 4. Guardar evidencia
    os.makedirs("data", exist_ok=True)
    with open("data/last_hunt_results.json", "w") as f:
        json.dump(all_results, f, indent=4)

    if not all_results:
        return f"Caza finalizada: No se encontraron anomalías para {equipo} en las {len(kql_queries)} reglas evaluadas."

    # 5. Pasar a Ollama para redactar (solo los primeros 5 para no saturar)
    print(f"   -> [Hunting] {len(all_results)} anomalías encontradas. Pidiendo informe a Ollama...")
    client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
    prompt = f"Eres un Threat Hunter. Hemos ejecutado reglas Sigma y encontramos {len(all_results)} eventos sospechosos. Aquí tienes una muestra:\n{json.dumps(all_results[:5])}\nRedacta un informe forense breve indicando el riesgo y qué investigar."
    
    try:
        ollama_response = client.chat.completions.create(
            model="qwen2.5:3b",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1
        )
        return ollama_response.choices[0].message.content
    except Exception as e:
        return f"Error con Ollama: {e}. Datos crudos: {json.dumps(all_results[:3])}"