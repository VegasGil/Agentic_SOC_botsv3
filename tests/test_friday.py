from agents.friday import friday
from tools.kql_runner import run_and_analyze

def test_friday_agent_initialization():
    # Ajustado al rol real de tu código
    assert friday.role == "Especialista DFIR"
    assert run_and_analyze in friday.tools
    assert friday.llm is not None