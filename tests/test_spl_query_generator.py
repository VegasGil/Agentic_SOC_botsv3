import pytest
from tools.spl_query_generator import generar_consulta_spl

def test_generar_consulta_spl(mocker):
    # Simulamos la respuesta de Ollama
    mock_response = mocker.patch("openai.resources.chat.completions.Completions.create")
    mock_response.return_value.choices = [
        mocker.Mock(message=mocker.Mock(content='search index=main "44d88612fea8a8f36de82e1278abb02f"'))
    ]
    
    resultado = generar_consulta_spl.run("Busca el hash 44d88612fea8a8f36de82e1278abb02f")
    assert "search index=main" in resultado
    assert "44d88612fea8a8f36de82e1278abb02f" in resultado