import os
import json
from crewai import Agent, LLM
from crewai.knowledge.source.text_file_knowledge_source import TextFileKnowledgeSource
from tools.kql_runner import run_and_analyze
from tools.verdict_sender import send_verdict
from tools.sigma_hunter import hunt_with_sigma

# 1. Cargar configuración
def cargar_config():
    ruta = os.path.join("config", "edith.json")
    with open(ruta, "r", encoding="utf-8") as f:
        return json.load(f)

config = cargar_config()

# 2. Configurar LLM y RAG
llm = LLM(
    model=config["model"],
    base_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
    temperature=config["temperature"]
)

knowledge_edith = TextFileKnowledgeSource(file_paths=["edith/test_rag_edith.txt"])

# 3. Definir Agente
edith = Agent(
    role=config["role"],
    goal=config["goal"],
    backstory=config["backstory"],
    tools=[run_and_analyze, send_verdict, hunt_with_sigma],
    llm=llm,
    verbose=True,
    max_iter=config["max_iter"],
    knowledge_sources=[knowledge_edith]
)

# ==========================================
# FUNCIONES (Intactas)
# ==========================================

def ejecutar_edith(equipo: str):
    print("🎯 E.D.I.T.H. iniciando Threat Hunting (Equipos Zombie)...")

    if os.getenv("AZURE_TENANT_ID") == "demo":
        print("   -> [DEMO MODE] E.D.I.T.H. no conecta a Azure real.")
        reporte = f"[DEMO] Auditoría simulada de Equipos Zombie para {equipo}."
        send_verdict.run(reporte, "E.D.I.T.H.")
        return reporte

    reporte_tecnico = run_and_analyze.run(
        playbook_filename='hunting_zombie_machines.kql',
        equipo=equipo,
        incidente="Auditoría de Equipos Zombie"
    )
    send_verdict.run(reporte_tecnico, "E.D.I.T.H.")
    return reporte_tecnico

def ejecutar_edith_sigma(equipo: str):
    print("🎯 E.D.I.T.H. iniciando Caza basada en Sigma (MITRE ATT&CK)...")

    if os.getenv("AZURE_TENANT_ID") == "demo":
        print("   -> [DEMO MODE] E.D.I.T.H. (Sigma) no conecta a Azure real.")
        reporte = f"[DEMO] Caza Sigma simulada para {equipo} (regla: sigma_hunting_mitre.yml)."
        send_verdict.run(reporte, "E.D.I.T.H. (Sigma Hunting)")
        return reporte

    ruta_sigma = "playbooks/sigma_hunting_mitre.yml"
    print(f"   -> Analizando regla: {ruta_sigma}")
    reporte_tecnico = hunt_with_sigma.run(ruta_sigma, equipo)

    # --- LEER EL CONOCIMIENTO (RAG MANUAL) ---
    conocimiento = ""
    try:
        with open("knowledge/edith/test_rag_edith.txt", "r", encoding="utf-8") as f:
            conocimiento = f.read()
    except FileNotFoundError:
        print("   -> [Aviso] No se encontró el archivo de conocimiento de Edith.")
    
    # --- PEDIR A OLLAMA QUE REDACTE USANDO EL CONOCIMIENTO ---
    print("   -> Solicitando a Ollama el informe (usando RAG)...")
    from openai import OpenAI
    client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
    prompt = f"""Eres E.D.I.T.H., una experta en Threat Hunting.
    
    Tu base de conocimiento dice:
    {conocimiento}
    
    Aquí tienes el reporte técnico de tu caza de amenazas:
    {reporte_tecnico}
    
    Redacta un informe ejecutivo (máx 6 líneas) usando tu conocimiento para priorizar el riesgo.
    """
    
    try:
        response = client.chat.completions.create(
            model="qwen2.5:3b",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1
        )
        reporte = response.choices[0].message.content
    except Exception as e:
        reporte = f"(Error Ollama) Reporte técnico:\n{reporte_tecnico}"

    print("   -> Enviando reporte a Splunk...")
    send_verdict.run(reporte, "E.D.I.T.H. (Sigma Hunting)")

    return reporte