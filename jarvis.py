import os
import json

# 1. FORZAR a CrewAI a usar Ollama ANTES de importar crewai
os.environ["EMBEDDINGS_OLLAMA_MODEL_NAME"] = "nomic-embed-text"
os.environ["EMBEDDINGS_OLLAMA_BASE_URL"] = "http://localhost:11434"
os.environ["EMBEDDINGS_PROVIDER"] = "ollama"

from dotenv import load_dotenv
load_dotenv()  # Carga .env

from crewai import Crew, Task
from agents.vision import vision
from tools.splunk_reader import fetch_splunk_alerts

# Importamos los ejecutores de los agentes (la lógica vive en cada archivo)
from agents.friday import ejecutar_friday
from agents.edith import ejecutar_edith
from agents.karen import ejecutar_karen

STATE_FILE = "data/state_alerts.json"

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                content = f.read().strip()
                if not content:          # archivo vacío → estado inicial
                    return []
                return json.loads(content)
        except (json.JSONDecodeError, ValueError):
            print("⚠️ state_alerts.json corrupto o vacío. Reiniciando estado.")
            return []
    return []

def save_state(state):
    os.makedirs("data", exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def procesar_alertas():
    # 1. Traer alertas de Splunk
    print(fetch_splunk_alerts.run())
    
    if not os.path.exists("data/splunk_alerts.json"):
        print("No hay archivo de alertas.")
        return

    with open("data/splunk_alerts.json", "r") as f:
        alertas = json.load(f)

    atendidas = load_state()

    if not alertas:
        print("No se encontraron alertas en Splunk.")
        return

    for alerta in alertas:
        alert_id = alerta.get("id", "unknown")
        equipo_afectado = alerta.get("computerDnsName", "falex")
        titulo = alerta.get("title", "Sin titulo")
        desc = alerta.get("description", "Sin descripcion")
        
        # 2. Verificar si ya fue atendida
        if alert_id in atendidas:
            print(f"[-] Alerta {alert_id} ya fue atendida anteriormente.")
            continue

        print(f"\n🚨 NUEVA ALERTA: {alert_id} - {titulo}")
        print(f"   Equipo afectado: {equipo_afectado}")
        
        # 3. Visión clasifica la alerta (con bypass de LLM en modo demo)
        if os.getenv("AZURE_TENANT_ID") == "demo":
            desc_lower = desc.lower()
            if "ransomware" in desc_lower or "malware" in desc_lower or "proceso" in desc_lower:
                decision = "FRIDAY"
            elif "zombie" in desc_lower:
                decision = "EDITH"
            elif "cve" in desc_lower:
                decision = "KAREN"
            else:
                decision = "FRIDAY"  # fallback
            print(f"🤖 [DEMO] Jarvis enruta a: {decision}")
        else:
            tarea_vision = Task(
                description=f"""Analiza esta alerta: '{titulo} - {desc}'.
                Determina quién debe investigar:
                - Si es Ransomware, Malware, Procesos -> Responde: FRIDAY
                - Si es Equipos Zombie -> Responde: EDITH
                - Si es CVE -> Responde: KAREN
                Responde SOLO con la palabra (FRIDAY, EDITH o KAREN).""",
                expected_output="FRIDAY, EDITH o KAREN",
                agent=vision
            )
            crew_vis = Crew(agents=[vision], tasks=[tarea_vision], verbose=False)
            decision = crew_vis.kickoff().raw.strip().upper()
            print(f"🤖 Jarvis enruta a: {decision}")

        # 4. ENRUTAMIENTO LIMPIO (Jarvis solo llama a la función)
        if "FRIDAY" in decision:
            reporte = ejecutar_friday(equipo_afectado, titulo)
            print("\n=== RESULTADO F.R.I.D.A.Y. ===")
            print(reporte)
            
        elif "EDITH" in decision:
            reporte = ejecutar_edith(equipo_afectado)
            print("\n=== RESULTADO E.D.I.T.H. ===")
            print(reporte)
            
        elif "KAREN" in decision:
            if "aspm" in desc.lower() or "codigo" in desc.lower() or "código" in desc.lower():
                reporte = ejecutar_karen(equipo_afectado, tipo_auditoria="aspm")
            else:
                reporte = ejecutar_karen(equipo_afectado)
            print("\n=== RESULTADO K.A.R.E.N. (RBVM) ===")
            print(reporte)
            
        else:
            print("⚠️ Jarvis no reconoció la decisión de Visión.")

        # 5. Marcar como atendida y guardar estado
        atendidas.append(alert_id)
        save_state(atendidas)
        print(f"✅ Alerta {alert_id} marcada como atendida.")


def ejecutar_orden_directa(orden: str):
    """Modo API: Despierta a Visión y ejecuta la orden específica."""
    print(f"🚀 [JARVIS] Recibida orden de la API: {orden}")
    
    # 1. Limpiamos el estado para forzar la investigación
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)
        print("🧹 Memoria limpiada. Investigando desde cero...")
        
    reporte_final = ""
    
    # 2. Ejecutamos a Visión (que a su vez despertará a los agentes)
    from agents.vision import vigilante_splunk
    
    if "todo" in orden or "máxima" in orden:
        print("🚨 [JARVIS] ALERTA MÁXIMA: Despertando a Visión...")
        reporte_final += vigilante_splunk('Visión, busca si hay algún malware en Splunk') or ""
        reporte_final += vigilante_splunk('Visión, busca si hay algún CVE en Splunk') or ""
        reporte_final += vigilante_splunk('Visión, hazme un barrido de reconocimiento en falex') or ""
    elif "cve" in orden:
        reporte_final = vigilante_splunk('Visión, busca si hay algún CVE en Splunk')
    elif "malware" in orden or "virus" in orden:
        reporte_final = vigilante_splunk('Visión, busca si hay algún malware en Splunk')
    elif "zombie" in orden or "barrido" in orden:
        reporte_final = vigilante_splunk('Visión, hazme un barrido de reconocimiento en falex')
        
    # Si vigilante_splunk no devuelve texto, usamos un mensaje genérico
    if not reporte_final:
        reporte_final = "He revisado Splunk y ejecutado los agentes. Revisa la consola para ver los detalles."
        
    return reporte_final

if __name__ == "__main__":
    print("🚀 Iniciando Jarvis (Modo Refactorizado con Agentes Autónomos)...")
    procesar_alertas()