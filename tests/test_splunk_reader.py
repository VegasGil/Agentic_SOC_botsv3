import os
from tools.splunk_reader import fetch_splunk_alerts

def test_splunk_reader_mock(mocker, monkeypatch):
    # 1. Inyectamos las credenciales ficticias en el entorno
    monkeypatch.setenv("SPLUNK_HOST", "https://localhost")
    monkeypatch.setenv("SPLUNK_PORT", "8088")
    monkeypatch.setenv("SPLUNK_REST_PORT", "8089")
    monkeypatch.setenv("SPLUNK_USER", "admin")
    monkeypatch.setenv("SPLUNK_PASS", "fake_password")

    # 2. Simulamos la petición HTTP
    mock_post = mocker.patch("tools.splunk_reader.requests.post")
    mock_post.return_value.status_code = 200
    mock_post.return_value.text = '{"result": {"_raw": "{\\"id\\": \\"test-1\\", \\"title\\": \\"Test Alert\\"}"}}\n'

    # 3. Simulamos la escritura en disco (para no crear archivos reales en GitHub)
    mocker.patch("builtins.open", mocker.mock_open())
    mocker.patch("os.makedirs")

    # 4. Ejecutamos la función
    resultado = fetch_splunk_alerts.run()

    # 5. Verificamos el resultado
    assert "Se encontraron 1 alertas" in resultado