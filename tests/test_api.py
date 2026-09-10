from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend import main
from backend.security import SecurityManager


class ApiIntegrationTests(unittest.TestCase):
    def test_controlled_lab_plan_is_exposed_to_dashboard(self) -> None:
        response = TestClient(main.app).get("/api/lab-plan")
        self.assertEqual(response.status_code, 200)
        plan = response.json()
        self.assertEqual(sum(item["percent"] for item in plan["partitions"]), 100)
        self.assertEqual(sum(item["sessions"] for item in plan["partitions"]), 30)
        self.assertEqual(sum(item["sessions"] for item in plan["scenarios"]), 30)
        self.assertTrue(any("held-out test" in gate for gate in plan["gates"]))

    def test_authenticated_telemetry_simulation_and_audit(self) -> None:
        original_security = main.security
        try:
            with tempfile.TemporaryDirectory() as directory:
                main.security = SecurityManager(Path(directory) / "security.db", secret="integration-secret")
                main.security.create_user("integration-admin", "integration-password", "admin")
                client = TestClient(main.app)
                login = client.post("/api/auth/login", json={"username": "integration-admin", "password": "integration-password"})
                self.assertEqual(login.status_code, 200)
                headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
                stream = client.post("/api/telemetry/streams", headers=headers, json={"source": "cowrie", "allowed_lateness": 0})
                self.assertEqual(stream.status_code, 200)
                stream_id = stream.json()["stream_id"]
                events = client.post(f"/api/telemetry/streams/{stream_id}/events", headers=headers, json={"flush": True, "records": [
                    {"eventid": "cowrie.login.failed", "timestamp": "2026-01-01T00:00:01Z", "src_ip": "192.0.2.1", "dst_ip": "10.0.0.5", "username": "root"},
                    {"eventid": "cowrie.login.failed", "timestamp": "2026-01-01T00:00:07Z", "src_ip": "192.0.2.2", "dst_ip": "10.0.0.5", "username": "root"},
                ]})
                self.assertEqual(events.status_code, 200)
                self.assertEqual(events.json()["host_graph"]["identity_reuse_count"], 1)
                simulation = client.post("/api/simulate", headers=headers, json={"action": "isolate_host"})
                self.assertLess(simulation.json()["after"], simulation.json()["before"])
                self.assertTrue(client.get("/api/admin/audit/verify", headers=headers).json()["valid"])
                self.assertEqual(client.post("/api/telemetry/streams", json={"source": "cowrie"}).status_code, 401)
        finally:
            main.security = original_security


if __name__ == "__main__":
    unittest.main()
