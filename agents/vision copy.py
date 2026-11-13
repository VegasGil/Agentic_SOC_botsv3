import os
import json
from crewai import Agent, LLM
from crewai.knowledge.source.text_file_knowledge_source import TextFileKnowledgeSource
from tools.splunk_reader import fetch_splunk_alerts

def cargar_config():
    ruta = os.path.join("config", "vision.json")
    with open(ruta, "r", encoding="utf-8") as f:
        return json.load(f)

config = cargar_config()

llm = LLM(
    model=config["model"],
    base_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
    temperature=config["temperature"]
)

# Creamos el agente
vision = Agent(
    role=config["role"],
    goal=config["goal"],
    backstory=config["backstory"],
    llm=llm,
    verbose=True
)
print("⚡ [VISIÓN] Agente inicializado.")

# ==========================================
# FUNCIÓN 1: PARA PRUEBAS POR TERMINAL (Con RAG)
# ==========================================
def ejecutar_vision(equipo: str, descripcion: str = ""):
    print("🧠 V.I.S.I.O.N. iniciando análisis con RAG...")
    
    conocimiento = ""
    try:
        with open("knowledge/vision/test_rag_vision.txt", "r", encoding="utf-8") as f:
            conocimiento = f.read()
    except FileNotFoundError:
        pass

    from openai import OpenAI
    client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
    
    prompt = f"""Eres V.I.S.I.O.N., el analista de triaje del SOC.
    Tu conocimiento dice: {conocimiento}
    
    El equipo afectado es {equipo}.
    La alerta dice: "{descripcion}"
    
    Basándote en tu conocimiento y en la alerta, decide qué agente debe investigar:
    - Si es un Equipo Zombie o hay tráfico inusual -> Responde: EDITH
    - Si es un malware o ransomware -> Responde: FRIDAY
    - Si es un tema de vulnerabilidades (CVE) -> Responde: KAREN
    
    Responde SOLO con la palabra (EDITH, FRIDAY o KAREN).
    """
    
    try:
        response = client.chat.completions.create(
            model="qwen2.5:3b",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0
        )
        decision_raw = response.choices[0].message.content.strip().upper()
        
        if "EDITH" in decision_raw:
            decision = "EDITH"
        elif "FRIDAY" in decision_raw:
            decision = "FRIDAY"
        elif "KAREN" in decision_raw:
            decision = "KAREN"
        else:
            decision = decision_raw
    except Exception as e:
        return f"(Error Ollama): {e}"

    print(f"🤖 Visión ha decidido enrutar a: {decision}")

    if decision == "EDITH":
        print("👉 Despertando a E.D.I.T.H. para Caza de Amenazas...")
        from agents.edith import ejecutar_edith
        return ejecutar_edith(equipo)
        
    elif decision == "FRIDAY":
        print("👉 Despertando a F.R.I.D.A.Y. para DFIR...")
        from agents.friday import ejecutar_friday
        return ejecutar_friday(equipo, descripcion or "Alerta de Visión")
        
    elif decision == "KAREN":
        print("👉 Despertando a K.A.R.E.N. para vulnerabilidades...")
        from agents.karen import ejecutar_karen
        return ejecutar_karen(equipo)
        
    else:
        return f"⚠️ Visión no reconoció la decisión: {decision}"

# ==========================================
# FUNCIÓN 2: ORQUESTADOR PRINCIPAL (Llamado por Jarvis)
# ==========================================
def vigilante_splunk(consulta_usuario: str = "¿Hay algo por ahí?"):
    print(f"🗣️ [JARVIS AL USUARIO]: Recibido. Voy a preguntarle a Visión...")
    print(f"🗣️ [JARVIS A VISIÓN]: '{consulta_usuario}'")
    
    from openai import OpenAI
    client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
    
    try:
        print("   -> [VISIÓN] Revisando Splunk...")
        fetch_splunk_alerts.run()
        
        with open("data/splunk_alerts.json", "r", encoding="utf-8") as f:
            alertas = json.load(f)
            
        print(f"   -> [VISIÓN] He leído {len(alertas)} alertas de Splunk.")
        
        resumen_alertas = ""
        for a in alertas:
            equipo_alerta = a.get('computerDnsName', 'Desconocido')
            resumen_alertas += f"- Equipo: {equipo_alerta} | Título: {a.get('title', '')} | Descripción: {a.get('description', '')}\n"

        prompt_analisis = f"""Eres V.I.S.I.O.N., el monitor del SOC.
        
        EL USUARIO PREGUNTA: "{consulta_usuario}"
        
        ESTAS SON LAS ALERTAS ACTUALES DE SPLUNK:
        {resumen_alertas}
        
        INSTRUCCIONES:
        1. Busca en las alertas algo que coincida con la pregunta del usuario (CVE, malware, zombie, etc.).
        2. Si ENCUENTRAS algo, extrae el equipo y recomienda al agente (KAREN para CVE, FRIDAY para Malware).
        3. Si NO ENCUENTRAS NADA, o si el usuario pide explícitamente un "barrido" o "reconocimiento", DEBES recomendar a EDITH para que haga Threat Hunting proactivo en el equipo 'falex' (o el que se mencione).
        
        Responde EXACTAMENTE en este formato:
        EQUIPO: [Nombre del equipo afectado o 'falex' por defecto]
        MOTIVO: [Breve explicación de lo que encontraste o por qué haces el barrido]
        AGENTE: [FRIDAY, EDITH, KAREN o NADA]
        """
        
        response = client.chat.completions.create(
            model="qwen2.5:3b",
            messages=[{"role": "user", "content": prompt_analisis}],
            temperature=0.0
        )
        
        respuesta_ollama = response.choices[0].message.content
        
        print("\n--- ANÁLISIS DE VISIÓN ---")
        print(respuesta_ollama)
        print("--------------------------\n")
        
        decision = "NADA"
        equipo_afectado = "falex" 
        motivo = "Barrido de reconocimiento"
        
        for linea in respuesta_ollama.split("\n"):
            if "EQUIPO:" in linea.upper():
                equipo_afectado = linea.split(":", 1)[1].strip()
            elif "MOTIVO:" in linea.upper():
                motivo = linea.split(":", 1)[1].strip()
            elif "AGENTE:" in linea.upper():
                linea_upper = linea.upper()
                if "KAREN" in linea_upper:
                    decision = "KAREN"
                elif "FRIDAY" in linea_upper:
                    decision = "FRIDAY"
                elif "EDITH" in linea_upper:
                    decision = "EDITH"
                    
        if decision == "NADA":
            print("👷 [JARVIS]: Entendido. No hay nada urgente, vuelvo a modo espera.")
            return "No hay nada urgente en Splunk."

        print(f"👷 [JARVIS]: Entendido. Visión me dice que el equipo es '{equipo_afectado}'.")
        print(f"👷 [JARVIS]: Me encargo de activar a {decision}. Motivo: {motivo}")
        
        # --- ENRUTAMIENTO CON RETURN ---
        if decision == "FRIDAY":
            from agents.friday import ejecutar_friday
            return ejecutar_friday(equipo_afectado, motivo)
            
        elif decision == "EDITH":
            from agents.edith import ejecutar_edith
            return ejecutar_edith(equipo_afectado)
            
        elif decision == "KAREN":
            from agents.karen import ejecutar_karen
            return ejecutar_karen(equipo_afectado)
            
        else:
            return f"Visión no reconoció la decisión: {decision}"
            
    except Exception as e:
        print(f"Error: {e}")
        return f"Error en el SOC: {e}"

# ==========================================
# FUNCIÓN 3: CHAT CON ALERTAS (Consultas en Lenguaje Natural)
# ==========================================
def chatear_con_alertas(pregunta: str):
    """Responde cualquier pregunta basada en las alertas de Splunk, sin activar agentes."""
    import json
    from openai import OpenAI
    from datetime import datetime  # <-- IMPORTANTE
    
    print(f"💬 [VISIÓN CHAT] Pregunta: {pregunta}")
    
    print("   -> [VISIÓN] Buscando alertas actuales en Splunk...")
    fetch_splunk_alerts.run()
    
    try:
        with open("data/splunk_alerts.json", "r", encoding="utf-8") as f:
            alertas = json.load(f)
            
        # 2. Preparamos el contexto con FECHAS AMIGABLES
        contexto = ""
        for a in alertas:
            fecha_raw = a.get('alertCreationTime', a.get('firstEventTime', ''))
            
            # Convertimos la fecha técnica a un formato legible
            # Convertimos la fecha técnica a un formato legible
            fecha_amigable = "Fecha desconocida"
            if fecha_raw:
                try:
                    fecha_dt = datetime.strptime(fecha_raw[:10], "%Y-%m-%d")
                    # Formato: "04/11/2026" (Más fácil de leer para el LLM)
                    fecha_amigable = fecha_dt.strftime("%d/%m/%Y") 
                except:
                    fecha_amigable = fecha_raw
                    
            contexto += f"- Título: {a.get('title', '')} | Equipo: {a.get('computerDnsName', '')} | Gravedad: {a.get('severity', '')} | Fecha: {fecha_amigable}\n"
            
        # 3. Leemos la configuración
        config_vision = cargar_config()
        personalidad = config_vision.get("backstory", "Eres un analista del SOC.")
        instrucciones_chat = config_vision.get("prompt_chat", "Responde la pregunta basándote en las alertas.")
        
        # 4. Construimos el prompt
        prompt = f"""{personalidad}
        
        PREGUNTA DEL USUARIO: {pregunta}
        
        ALERTAS DISPONIBLES (Título | Equipo | Gravedad | Fecha):
        {contexto}
        
        INSTRUCCIONES EXTRA PARA FECHAS:
        - Si el usuario pregunta por una fecha, fíjate en el campo "Fecha" o en el formato YYYY-MM-DD.
        - Si el usuario dice "noviembre", busca en las fechas que digan "November" o "11".
        
        INSTRUCCIONES GENERALES:
        {instrucciones_chat}
        """
        
        # 5. Le pedimos a Ollama que responda
        client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
        
        response = client.chat.completions.create(
            model="qwen2.5:3b",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1
        )
        
        respuesta = response.choices[0].message.content.strip()
        
        # 🚨 FILTRO DE SEGURIDAD
        if not respuesta or respuesta == "-" or respuesta == "*" or respuesta == "-\n":
            return "No hay alertas que coincidan con esa búsqueda."
            
        respuesta = respuesta.replace("-\n", "").strip()
        if not respuesta:
            return "No hay alertas que coincidan con esa búsqueda."
            
        return respuesta
        
    except Exception as e:
        return f"Error al consultar alertas: {e}"
