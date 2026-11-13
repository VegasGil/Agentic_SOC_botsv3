import os

def test_docker_files_exist():
    assert os.path.exists("Dockerfile"), "El Dockerfile no existe"
    assert os.path.exists("docker-compose.yml"), "El docker-compose.yml no existe"
    assert os.path.exists(".env.demo"), "El .env.demo no existe"

def test_dockerfile_content():
    with open("Dockerfile", "r") as f:
        content = f.read()
    assert "FROM python" in content, "El Dockerfile no tiene una imagen base de Python"
    assert "requirements.txt" in content, "El Dockerfile no instala los requirements"
    assert "jarvis" in content or "CMD" in content, "El Dockerfile no tiene un CMD"

def test_demo_mode_exists():
    with open("tools/kql_raw_fetcher.py", "r") as f:
        content = f.read()
    assert "AZURE_TENANT_ID" in content and "demo" in content, "El Modo Demo no está implementado en kql_raw_fetcher.py"