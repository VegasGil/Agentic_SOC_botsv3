import pytest
from unittest.mock import patch, MagicMock
from tools.sigma_hunter import hunt_with_sigma

def test_sigma_hunter_multiple_rules(mocker):
    # 1. Simulamos el archivo Sigma
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch("builtins.open", mocker.mock_open(read_data="title: Regla 1\n---\ntitle: Regla 2"))
    mocker.patch("os.makedirs")
    mocker.patch("json.dump")

    # 2. Simulamos la traducción de Sigma (que devuelva 2 consultas)
    mock_sigma = mocker.patch("tools.sigma_hunter.SigmaCollection.from_yaml")
    mock_backend = mocker.patch("tools.sigma_hunter.KustoBackend")
    mock_backend.return_value.convert.return_value = ["Query 1", "Query 2"]

    # 3. Simulamos Azure (autenticación y respuestas)
    mock_msal = mocker.patch("msal.ConfidentialClientApplication")
    mock_msal.return_value.acquire_token_for_client.return_value = {"access_token": "fake_token"}
    
    mock_requests = mocker.patch("requests.post")
    # Simulamos que la Query 1 encuentra algo, pero la Query 2 no.
    mock_response_1 = MagicMock()
    mock_response_1.status_code = 200
    mock_response_1.json.return_value = {"Results": [{"DeviceName": "falex", "Alert": "Suspicious"}]}
    
    mock_response_2 = MagicMock()
    mock_response_2.status_code = 200
    mock_response_2.json.return_value = {"Results": []}
    
    mock_requests.side_effect = [mock_response_1, mock_response_2]

    # 4. Simulamos Ollama
    mock_openai = mocker.patch("tools.sigma_hunter.OpenAI")
    mock_client = mock_openai.return_value
    mock_completion = MagicMock()
    mock_completion.choices = [MagicMock(message=MagicMock(content="Informe multi-regla simulado"))]
    mock_client.chat.completions.create.return_value = mock_completion

    # 5. Ejecutamos
    resultado = hunt_with_sigma.run("ruta_falsa.yml", "falex")

    # 6. Verificamos
    assert "Informe multi-regla simulado" in resultado
    assert mock_requests.call_count == 2  # Debe haber ejecutado las 2 consultas