from agents.vision import vision

def test_vision_agent_initialization():
    from agents.vision import vision
    assert vision.role is not None
    assert "Analista" in vision.role 