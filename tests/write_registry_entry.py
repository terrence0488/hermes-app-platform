"""Write a registry entry with the real gatekeeper code, for the router's cross-component test.

Usage: write_registry_entry.py <registry_dir> <name> <port> [guest ...]
"""
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parent.parent
loader = importlib.machinery.SourceFileLoader("gatekeeper", str(root / "gatekeeper/hermes-app-gatekeeper"))
spec = importlib.util.spec_from_loader("gatekeeper", loader)
gk = importlib.util.module_from_spec(spec)
loader.exec_module(gk)
gk.check_listener = lambda port, settings: None
os.chown = lambda *a, **k: None
registry, name, port, guests = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4:]
with tempfile.TemporaryDirectory() as tmp:
    base = pathlib.Path(tmp)
    (base / "new").mkdir()
    (base / "results").mkdir()
    config = {"domain": "example.net", "agent_user": "a", "requester_user": "h", "registry_group": "r",
              "result_group": "h", "reserved_names": ["hermes"], "inbox_dir": str(base / "new"),
              "result_dir": str(base / "results"), "registry_dir": registry, "port_min": 1024, "port_max": 65535}
    (base / "c.json").write_text(json.dumps(config))
    settings = gk.Settings(str(base / "c.json"))
    settings.__class__ = type("S", (gk.Settings,), {"requester_uid": os.getuid(), "agent_uid": 0,
                                                    "registry_gid": os.getgid(), "result_gid": os.getgid()})
    requests = [{"action": "publish", "name": name, "port": port}]
    if guests:
        requests.append({"action": "grant", "name": name, "emails": guests})
    for number, request in enumerate(requests):
        request_id = f"{number:032x}"
        (base / "new" / f"{request_id}.json").write_text(json.dumps(
            {"id": request_id, "requested_by": "telegram:1", **request}))
        gk.process_requests(settings)
        result = json.loads((base / "results" / f"{request_id}.json").read_text())
        if result["status"] != "ok":
            sys.exit(result["reason"])
