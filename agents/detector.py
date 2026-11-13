import os
import json
from crewai import Agent, LLM
from crewai.knowledge.source.text_file_knowledge_source import TextFileKnowledgeSource
from tools.sigma_converter import convert_sigma_to_kql

# 1. Cargar configuración
def cargar_config():
    ruta = os.path.join("config", "detector.json")
    with open(ruta, "r", encoding="utf-8") as f:
        return json.load(f)

config = cargar_config()

# 2. Configurar LLM y RAG
llm = LLM(
    model=config["model"],
    base_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
    temperature=config["temperature"]
)

knowledge_detector = TextFileKnowledgeSource(file_paths=["detector/test_rag_detector.txt"])

# 3. Definir el Agente
detector = Agent(
    role=config["role"],
    goal=config["goal"],
    backstory=config["backstory"],
    tools=[convert_sigma_to_kql],
    llm=llm,
    verbose=True,
    max_iter=config["max_iter"],
    knowledge_sources=[knowledge_detector]
)

# ==========================================
# FUNCIÓN (Intacta)
# ==========================================

def ejecutar_detector(ruta_sigma: str):
    """Lee un archivo YAML y lo traduce a KQL."""
    if not os.path.exists(ruta_sigma):
        return f"Error: No se encontró el archivo {ruta_sigma}"
        
    with open(ruta_sigma, "r", encoding="utf-8") as f:
        yaml_content = f.read()
        
    print(f"⚙️ D.E.T.E.C.T.O.R. traduciendo {ruta_sigma}...")
    kql = convert_sigma_to_kql.run(yaml_content)
    return kql