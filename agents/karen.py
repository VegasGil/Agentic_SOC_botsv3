import os
import json
from crewai import Agent, LLM
from crewai.knowledge.source.text_file_knowledge_source import TextFileKnowledgeSource
from tools.kql_raw_fetcher import fetch_cves_raw
from tools.rbvm_enricher import prioritize_cves
from tools.aspm_tool import scan_application_aspm
from tools.verdict_sender import send_verdict
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# 1. Cargar la configuración desde el JSON
def cargar_config():
    ruta = os.path.join("config", "karen.json")
    with open(ruta, "r", encoding="utf-8") as f:
        return json.load(f)

config = cargar_config()

# 2. Configurar LLM y Conocimiento para el Agente de CrewAI
llm = LLM(
    model=config["model"],
    base_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
    temperature=config["temperature"]
)

knowledge_karen = TextFileKnowledgeSource(file_paths=["karen/test_rag_karen.txt"])

# 3. Definir el Agente (por si usas karen.kickoff())
karen = Agent(
    role=config["role"],
    goal=config["goal"],
    backstory=config["backstory"],
    tools=[fetch_cves_raw, prioritize_cves, scan_application_aspm, send_verdict],
    llm=llm,
    verbose=True,
    max_iter=config["max_iter"],
    knowledge_sources=[knowledge_karen]
)

# 4. Función principal
def ejecutar_karen(equipo: str, tipo_auditoria: str = "infraestructura"):
    print(f"🛡️ K.A.R.E.N. iniciando Auditoría ({tipo_auditoria})...")

    # --- BYPASS DEMO ---
    if os.getenv("AZURE_TENANT_ID") == "demo":
        print("   -> [DEMO MODE] K.A.R.E.N. simula la auditoría (sin Azure/Ollama).")
        if tipo_auditoria == "aspm":
            reporte_tecnico = "[DEMO] Escaneo ASPM simulado: 0 vulnerabilidades críticas."
        else:
            reporte_tecnico = (
                f"[DEMO] CVEs simuladas para {equipo}: "
                "CVE-2021-44228 (Critical, KEV: SÍ), CVE-2024-1234 (High). Prioridad: CRÍTICA."
            )
        informe_ejecutivo = (
            f"[DEMO] Informe ejecutivo K.A.R.E.N. para {equipo}: "
            "se detectaron CVEs críticas. Recomendación: PARCHE INMEDIATO (24h)."
        )
        print("   -> Enviando reporte a Splunk...")
        send_verdict.run(informe_ejecutivo, "K.A.R.E.N.")
        return informe_ejecutivo
    # --- FIN BYPASS DEMO ---

    # FASE 1: Obtener datos
    if tipo_auditoria == "aspm":
        reporte_tecnico = scan_application_aspm.run(target_path=".")
    else:
        cves_json = fetch_cves_raw.run(equipo)
        reporte_tecnico = prioritize_cves.run(cves_json)

    # FASE 2: Pasar a Ollama para redactar el informe final (Usando el archivo .txt)
    print("   -> Solicitando a Ollama el informe ejecutivo (usando RAG)...")
    
    # --- LEER EL CONOCIMIENTO ---
    conocimiento = ""
    try:
        with open("knowledge/karen/test_rag_karen.txt", "r", encoding="utf-8") as f:
            conocimiento = f.read()
    except FileNotFoundError:
        print("   -> [Aviso] No se encontró el archivo de conocimiento de Karen.")

    ollama_base = os.getenv("OLLAMA_URL", "http://localhost:11434")
    client = OpenAI(base_url=f"{ollama_base}/v1", api_key="ollama")
    
    prompt = f"""Eres un experto en ciberseguridad y gestión de vulnerabilidades.
    
    Tu política de parcheo dice:
    {conocimiento}
    
    Aquí tienes el reporte técnico de las CVEs encontradas:
    {reporte_tecnico}
    
    Instrucciones:
    1. Basándote en tu política de parcheo, decide si es CRÍTICA (24h) o BAJA.
    2. Redacta un resumen ejecutivo (máx 4 líneas) directo y accionable.
    """
    
    try:
        response = client.chat.completions.create(
            model="qwen2.5:3b",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1
        )
        informe_ejecutivo = response.choices[0].message.content
    except Exception as e:
        informe_ejecutivo = f"(Error Ollama) Reporte técnico:\n{reporte_tecnico}"

    print("   -> Enviando reporte a Splunk...")
    send_verdict.run(informe_ejecutivo, "K.A.R.E.N.")
    
    return informe_ejecutivo