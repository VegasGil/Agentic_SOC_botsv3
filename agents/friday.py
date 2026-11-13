import os
from crewai import Agent, LLM
from crewai.knowledge.source.text_file_knowledge_source import TextFileKnowledgeSource

# Herramientas base
from tools.kql_runner import run_and_analyze
from tools.verdict_sender import send_verdict

# Nuevas herramientas de Threat Intelligence
from tools.virustotal_tool import consultar_virustotal
from tools.phishing_tool import detectar_phishing

llm = LLM(model="ollama_chat/qwen2.5:3b", base_url="http://localhost:11434", temperature=0.1)

# 1. CREAS LA FUENTE DE CONOCIMIENTO
knowledge_friday = TextFileKnowledgeSource(
    file_paths=["friday/test_rag_friday.txt"] 
)

# 2. DEFINIMOS EL AGENTE CON LAS NUEVAS HERRAMIENTAS
friday = Agent(
    role="Especialista DFIR",
    goal="Investigar alertas ejecutando playbooks KQL en Microsoft Defender, consultar Threat Intel (VirusTotal/Phishing) y redactar informes.",
    backstory="Eres F.R.I.D.A.Y., una IA forense experta. Sabes usar KQL para encontrar el origen de un ataque. También puedes consultar la reputación de IPs en VirusTotal y detectar dominios de Phishing.",
    tools=[run_and_analyze, send_verdict, consultar_virustotal, detectar_phishing], # <-- HERRAMIENTAS AÑADIDAS
    llm=llm,
    verbose=True,
    max_iter=5,
    knowledge_sources=[knowledge_friday]
)

# ==========================================
# FUNCIONES (Tu código original intacto)
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