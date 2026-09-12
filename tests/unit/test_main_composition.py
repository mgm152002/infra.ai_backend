from pathlib import Path


def test_main_is_only_an_application_composition_root():
    source = Path("main.py").read_text()

    assert len(source.splitlines()) < 300
    assert "@app." not in source
    assert "def process_chat_request" not in source
    assert "def infra_automation_ai" not in source
