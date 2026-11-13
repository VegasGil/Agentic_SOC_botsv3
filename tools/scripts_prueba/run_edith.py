import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Importamos la herramienta unificada
from tools.kql_runner import run_and_analyze

def test_edith():
    print("🎯 Iniciando E.D.I.T.H. (Caza proactiva en Azure)...")
    
    # Python llama directo a la herramienta, sin CrewAI
    resultado = run_and_analyze.run(
        playbook_filename='hunting_zombie_machines.kql',
        equipo='cualquiera',
        incidente='Auditoría de Equipos'
    )
    
    print("\n=== 🧠 INFORME DE E.D.I.T.H. ===")
    print(resultado)

if __name__ == "__main__":
    test_edith()