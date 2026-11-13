import pytest
from tools.splunk_verdict_reader import ejecutar_consulta_spl

def test_ejecutar_consulta_spl_mock(mocker):
    """
    Prueba que el lector de Splunk procese correctamente una respuesta simulada
    (sin conectarse a Internet ni requerir credenciales reales).
    """
    # Simulamos la respuesta HTTP de Splunk
    mock_post = mocker.patch("requests.post")
    mock_post.return_value.status_code = 200
    mock_post.return_value.raise_for_status.return_value = None
    
    # Simulamos el texto JSON que devolvería Splunk
    mock_post.return_value.text = '{"result": {"_raw": "{\\"verdict\\": \\"MALICIOUS\\", \\"source_agent\\": \\"Nirvana\\"}", "_time": "2026-11-12T10:00:00Z"}}'

    # Ejecutamos la función
    resultado = ejecutar_consulta_spl.run(query_spl='search index=main "test"')

    # Verificamos que el resultado contenga lo que esperamos
    assert "Splunk devolvió 1 resultados" in resultado
    assert "MALICIOUS" in resultado
    assert "Nirvana" in resultado