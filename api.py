from fastapi import FastAPI
from pydantic import BaseModel
from jarvis import ejecutar_orden_directa
from agents.friday import friday  # <-- IMPORTAMOS A FRIDAY

app = FastAPI(title="Agentic-SOC API")

class Pregunta(BaseModel):
    texto: str

# 1. FLUJO NORMAL (Visión decide)
@app.post("/preguntar")
def preguntar(pregunta: Pregunta):
    print(f"📡 [API] Recibida pregunta estándar: {pregunta.texto}")
    reporte = ejecutar_orden_directa(pregunta.texto.lower())
    return {"respuesta": reporte}

# 2. NUEVO FLUJO: THREAT INTEL (Friday va directo)
@app.post("/threat-intel")
def threat_intel(pregunta: Pregunta):
    print(f"📡 [API] Petición de Threat Intel (IOC) recibida: {pregunta.texto}")
    resultado = friday.kickoff(pregunta.texto)
    
    # 🚨 EXTRAEMOS SOLO EL TEXTO PARA QUE NIRVANA LO ENVÍE LIMPIO A SLACK
    if hasattr(resultado, 'raw'):
        return {"respuesta": resultado.raw}
    return {"respuesta": str(resultado)}