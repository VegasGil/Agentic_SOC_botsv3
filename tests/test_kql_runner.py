import pytest
from unittest.mock import MagicMock, mock_open
from tools.kql_runner import run_and_analyze

def test_kql_runner_mock(mocker):
    # 1. Simulamos que el archivo .kql existe
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch("builtins.open", mock_open(read_data="DeviceLogonEvents | take 1"))

    # 2. Simulamos la respuesta de Azure
    mock_requests = mocker.patch("requests.post")
    mock_response = mock_requests.return_value
    mock_response.status_code = 200
    mock_response.json.return_value = {"Results": [{"AccountName": "root"}]}

    # 3. Simulamos la respuesta de Ollama usando la ruta exacta (kql_runner.OpenAI)
    mock_openai_class = mocker.patch("tools.kql_runner.OpenAI")
    mock_client = mock_openai_class.return_value
    mock_completion = MagicMock()
    mock_completion.choices = [MagicMock(message=MagicMock(content="Informe simulado de Ollama"))]
    mock_client.chat.completions.create.return_value = mock_completion

    # 4. Ejecutamos la herramienta
    resultado = run_and_analyze.run(
        playbook_filename="test.kql", 
        equipo="falex", 
        incidente="Malware Test"
    )
    
    # 5. Verificamos que el informe final contenga el texto simulado
    assert "Informe simulado de Ollama" in resultado