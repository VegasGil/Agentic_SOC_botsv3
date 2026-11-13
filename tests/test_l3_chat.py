import pytest
from agents.l3_chat import iniciar_l3_chat, obtener_evidencia, config_l3

def test_l3_chat_config_loads():
    """Verifica que el JSON de configuración existe y se lee bien."""
    assert "system_prompt" in config_l3
    assert "palabras_clave" in config_l3

def test_l3_chat_evidence_tool(mocker):
    """Verifica que la herramienta de evidencia maneja bien si no hay archivos."""
    mocker.patch("glob.glob", return_value=[])
    resultado = obtener_evidencia("falex")
    assert "No hay archivos" in resultado or "Error" in resultado