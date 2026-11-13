import os
import json
from datetime import datetime
from crewai import Agent, LLM
from openai import OpenAI
from tools.splunk_reader import fetch_splunk_alerts
from tools.splunk_verdict_reader import ejecutar_consulta_spl

def cargar_config():
    ruta = os.path.join("config", "vision.json")
    with open(ruta, "r", encoding="utf-8") as f:
        return json.load(f)

config = cargar_config()

llm = LLM(
    model=f"ollama_chat/{config['model']}",
    base_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
    temperature=config["temperature"]
)

vision = Agent(
    role=config["role"],
    goal=config["goal"],
    backstory=config["backstory"],
    tools=[ejecutar_consulta_spl],
    llm=llm,
    verbose=True
)
print("⚡ [VISIÓN] Agente inicializado.")

client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")

# ==========================================
# FUNCIÓN 1: TRIAGE INICIAL (Con reglas del JSON)
# ==========================================
def ejecutar_vision(equipo: str, descripcion: str = ""):
    print("🧠 V.I.S.I.O.N. iniciando análisis...")
    
    # 1. Lógica de derivación por reglas (leídas del JSON)
    reglas = config.get("reglas_derivacion", {})
    for agente_destino, palabras_clave in reglas.items():
        for palabra in palabras_clave:
            if palabra.lower() in descripcion.lower():
                print(f"👉 [Visión] Detectado '{palabra}'. Derivando a {agente_destino}...")
                
                if agente_destino.upper() == "FRIDAY":
                    from agents.friday import friday
                    return friday.kickoff(descripcion)
                elif agente_destino.upper() == "EDITH":
                    from agents.edith import ejecutar_edith
                    return ejecutar_edith(equipo)
                elif agente_destino.upper() == "KAREN":
                    from agents.karen import ejecutar_karen
                    return ejecutar_karen(equipo)

    # 2. Si no hay reglas, usamos el LLM con el prompt del JSON
    prompt_triaje = config["prompts"]["triaje"].format(equipo=equipo, descripcion=descripcion)
    
    try:
        response = client.chat.completions.create(
            model=config["model"],
            messages=[{"role": "user", "content": prompt_triaje}],
            temperature=0.0
        )
        decision = response.choices[0].message.content.strip().upper()
        
        if "EDITH" in decision:
            from agents.edith import ejecutar_edith
            return ejecutar_edith(equipo)
        elif "FRIDAY" in decision:
            from agents.friday import ejecutar_friday
            return ejecutar_friday(equipo, descripcion)
        elif "KAREN" in decision:
            from agents.karen import ejecutar_karen
            return ejecutar_karen(equipo)
        else:
            return f"⚠️ Visión no reconoció la decisión: {decision}"
    except Exception as e:
        return f"(Error Ollama): {e}"

# ==========================================
# FUNCIÓN 2: ORQUESTADOR DINÁMICO (Busca en Splunk el equipo que le pidas)
# ==========================================
def vigilante_splunk(consulta_usuario: str = "¿Hay algo por ahí?"):
    print(f"🗣️ [JARVIS A VISIÓN]: '{consulta_usuario}'")
    
    # 1. Extraemos el equipo de la consulta del usuario (Búsqueda dinámica)
    # Si el usuario pide "btun-l", buscamos "btun-l". Si pide "falex", buscamos "falex".
    if "barrido" in consulta_usuario.lower() or "algo" in consulta_usuario.lower():
        query = 'search (index=main OR index=botsv3) | head 5'
    else:
        # Limpiamos la frase para quedarnos con la palabra clave (ej. "btun-l")
        palabras = consulta_usuario.split()
        equipo_buscado = palabras[-1] if len(palabras) > 0 else "falex"
        query = f'search (index=main OR index=botsv3) "{equipo_buscado}" | head 5'

    print(f"   -> [VISIÓN] Buscando en Splunk: {query}")
    resultado_splunk = ejecutar_consulta_spl.run(query_spl=query)
    
    if "No se encontraron resultados" in resultado_splunk:
        return "No hay alertas pendientes en Splunk para esa búsqueda."

    # 2. Analiza lo encontrado con Ollama
    print(f"   -> [VISIÓN] Alertas encontradas. Analizando...")
    
    prompt_analisis = config["prompts"]["analisis_splunk"].format(
        resultado_splunk=resultado_splunk,
        consulta_usuario=consulta_usuario
    )
    
    try:
        response = client.chat.completions.create(
            model=config["model"],
            messages=[{"role": "user", "content": prompt_analisis}],
            temperature=0.0
        )
        
        respuesta_ollama = response.choices[0].message.content
        print(f"\n--- ANÁLISIS DE VISIÓN ---\n{respuesta_ollama}\n--------------------------\n")
        
        decision = "NADA"
        equipo_afectado = "desconocido"
        motivo = "Análisis de alertas"
        
        for linea in respuesta_ollama.split("\n"):
            if "EQUIPO:" in linea.upper():
                equipo_afectado = linea.split(":", 1)[1].strip()
            elif "MOTIVO:" in linea.upper():
                motivo = linea.split(":", 1)[1].strip()
            elif "AGENTE:" in linea.upper():
                linea_upper = linea.upper()
                if "KAREN" in linea_upper: decision = "KAREN"
                elif "FRIDAY" in linea_upper: decision = "FRIDAY"
                elif "EDITH" in linea_upper: decision = "EDITH"
                    
        if decision == "NADA":
            print("👷 [JARVIS]: Entendido. No hay nada urgente.")
            return "No hay nada urgente en Splunk."

        print(f"👷 [JARVIS]: Activando a {decision} para '{equipo_afectado}'. Motivo: {motivo}")
        
        if decision == "FRIDAY":
            from agents.friday import ejecutar_friday
            return ejecutar_friday(equipo_afectado, motivo)
        elif decision == "EDITH":
            from agents.edith import ejecutar_edith
            return ejecutar_edith(equipo_afectado)
        elif decision == "KAREN":
            from agents.karen import ejecutar_karen
            return ejecutar_karen(equipo_afectado)
            
    except Exception as e:
        return f"Error en el análisis de Visión: {e}"

# ==========================================
# FUNCIÓN 3: CHAT CON ALERTAS (Consultas en Lenguaje Natural)
# ==========================================
def chatear_con_alertas(pregunta: str):
    print(f"💬 [VISIÓN CHAT] Pregunta: {pregunta}")
    print("   -> [VISIÓN] Buscando alertas actuales en Splunk...")
    fetch_splunk_alerts.run()
    
    try:
        with open("data/splunk_alerts.json", "r", encoding="utf-8") as f:
            alertas = json.load(f)
            
        contexto = ""
        for a in alertas:
            fecha_raw = a.get('alertCreationTime', a.get('firstEventTime', ''))
            fecha_amigable = "Fecha desconocida"
            if fecha_raw:
                try:
                    fecha_dt = datetime.strptime(fecha_raw[:10], "%Y-%m-%d")
                    fecha_amigable = fecha_dt.strftime("%d/%m/%Y") 
                except:
                    fecha_amigable = fecha_raw
            contexto += f"- Título: {a.get('title', '')} | Equipo: {a.get('computerDnsName', '')} | Gravedad: {a.get('severity', '')} | Fecha: {fecha_amigable}\n"
            
        prompt = f"""{config['backstory']}
        
        PREGUNTA: {pregunta}
        
        ALERTAS:
        {contexto}
        
        INSTRUCCIONES EXTRA:
        {config['prompts']['chat_alertas']}
        """
        
        response = client.chat.completions.create(
            model=config["model"],
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1
        )
        
        respuesta = response.choices[0].message.content.strip()
        
        if not respuesta or respuesta in ["-", "*", "-\n"]:
            return "No hay alertas que coincidan con esa búsqueda."
            
        return respuesta.replace("-\n", "").strip()
        
    except Exception as e:
        return f"Error al consultar alertas: {e}"