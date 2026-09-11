"""Characterization tests for the application's HTTP contract."""

import json
from pathlib import Path


def test_main_exposes_the_existing_route_contract():
    from main import app
    from tests.route_contract import collect_route_contract

    contract = collect_route_contract(app)
    expected = {
        tuple(item)
        for item in json.loads(Path("tests/fixtures/route_contract.json").read_text())
    }
    required = {
        ("/chat", "POST"),
        ("/chat/stream", "POST"),
        ("/cmdb", "GET"),
        ("/uploadCMDB", "POST"),
        ("/incidentAdd", "POST"),
        ("/incidents/all", "GET"),
        ("/alert-types", "GET"),
        ("/pending-actions", "GET"),
        ("/admin/health", "GET"),
        ("/worker/queue-health", "GET"),
        ("/addKnowledge", "POST"),
        ("/getKnowledge", "GET"),
    }

    assert required <= contract
    assert contract == expected
