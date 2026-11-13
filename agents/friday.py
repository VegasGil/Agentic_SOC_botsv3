import os
import json
from crewai import Agent, LLM
from crewai.knowledge.source.text_file_knowledge_source import TextFileKnowledgeSource

# Herramientas
from tools.kql_runner import run_and_analyze
from tools.verdict_sender import send_verdict
from tools.virustotal_tool import consultar_virustotal
from tools.phishing_tool import detectar_phishing
from tools.splunk_verdict_reader import ejecutar_consulta_spl  # 🚨 Nueva herramienta (Switch)

# 1. CARGAR LA CONFIGURACIÓN (JSON)
def cargar_config_friday():
    ruta = os.path.join("config", "friday.json")
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ Error cargando config de F.R.I.D.A.Y.: {e}")
        return {
            "role": "Especialista DFIR",
            "goal": "Investigar alertas.",
            "backstory": "Eres F.R.I.D.A.Y.",
            "model": "ollama_chat/qwen2.5:3b",
            "temperature": 0.1,
            "max_iter": 5
        }

config = cargar_config_friday()

# 2. INICIALIZAR EL LLM CON LOS DATOS DEL JSON
llm = LLM(
    model=config["model"], 
    base_url="http://localhost:11434", 
    temperature=config["temperature"]
)

# 3. CREAR LA FUENTE DE CONOCIMIENTO
knowledge_friday = TextFileKnowledgeSource(
    file_paths=["friday/test_rag_friday.txt"] 
)

# 4. DEFINIR EL AGENTE LEYENDO EL JSON
friday = Agent(
    role=config["role"],
    goal=config["goal"],
    backstory=config["backstory"], # <-- Aquí lee la historia que menciona Splunk
    tools=[
        run_and_analyze, 
        send_verdict, 
        consultar_virustotal, 
        detectar_phishing,
        ejecutar_consulta_spl # <-- Aquí le entregamos la herramienta física
    ],
    llm=llm,
    verbose=True,
    max_iter=config["max_iter"],
    knowledge_sources=[knowledge_friday]
)

# ==========================================
# FUNCIONES ORIGINALES (Intactas)
# ==========================================

def ejecutar_friday(equipo: str, incidente: str):
    print("🕵️ F.R.I.D.A.Y. iniciando DFIR...")

    # --- BYPASS DEMO ---
    if os.getenv("AZURE_TENANT_ID") == "demo":
        print("   -> [DEMO MODE] F.R.I.D.A.Y. no conecta a Azure real.")
        reporte_final = (
            f"[DEMO] Análisis simulado para {equipo} sobre '{incidente}'.\n"
            "Logins: sin conexión a Azure (modo demo).\n"
            "Procesos: sin conexión a Azure (modo demo)."
        )
        print("   -> Enviando reporte a Splunk...")
        send_verdict.run(reporte_final, "F.R.I.D.A.Y.")
        return reporte_final
    # --- FIN BYPASS DEMO ---

    print("   -> Buscando Logins...")
    res1 = run_and_analyze.run(
        playbook_filename='dfir_fase1_identificacion.kql',
        equipo=equipo,
        incidente=incidente
    )

    print("   -> Buscando Procesos...")
    res2 = run_and_analyze.run(
        playbook_filename='dfir_fase2_procesos.kql',
        equipo=equipo,
        incidente=incidente
    )

    reporte_final = f"Logins:\n{res1}\nProcesos:\n{res2}"

    print("   -> Enviando reporte a Splunk...")
    send_verdict.run(reporte_final, "F.R.I.D.A.Y.")

    return reporte_final

def ejecutar_edith_hunting(equipo: str):
    print("🎯 E.D.I.T.H. iniciando Caza Proactiva (0-Day / LotL)...")

    if os.getenv("AZURE_TENANT_ID") == "demo":
        print("   -> [DEMO MODE] E.D.I.T.H. no conecta a Azure real.")
        reporte = f"[DEMO] Caza simulada para {equipo}: sin conexión a Azure (modo demo)."
        print("   -> Enviando reporte a Splunk...")
        send_verdict.run(reporte, "E.D.I.T.H.")
        return reporte

    print("   -> Buscando descargas sospechosas en Azure...")
    reporte = run_and_analyze.run(
        playbook_filename='hunting_suspicious_processes.kql',
        equipo=equipo,
        incidente="Caza de Amenazas (Comportamiento Anómalo)"
    )

    print("   -> Enviando reporte a Splunk...")
    send_verdict.run(reporte, "E.D.I.T.H.")

    return reporte