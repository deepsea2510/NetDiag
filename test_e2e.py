"""端到端测试：REST 端点 + WebSocket 实时推送。"""
import asyncio
import json
import urllib.request
import websockets

BASE = "http://127.0.0.1:8899"
WS = "ws://127.0.0.1:8899/ws"


def post(path, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(BASE + path, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


async def test_ws(action, payload):
    async with websockets.connect(WS) as ws:
        await ws.send(json.dumps({"action": action, **payload}))
        msgs = []
        while True:
            m = json.loads(await asyncio.wait_for(ws.recv(), timeout=30))
            msgs.append(m)
            if m["type"] == "done":
                break
        return msgs


def main():
    # 首页
    with urllib.request.urlopen(BASE + "/", timeout=5) as r:
        html = r.read().decode()
    assert "NetDiag" in html
    print("[OK] 首页 HTML 加载成功")

    # health
    h = json.loads(urllib.request.urlopen(BASE + "/api/health", timeout=5).read())
    assert h["status"] == "ok"
    print("[OK] /api/health:", h)

    # REST ping
    p = post("/api/ping", {"targets": "127.0.0.1, 8.8.8.8", "count": 2, "timeout": 1000, "workers": 4})
    assert p["targets"] == 2
    print("[OK] /api/ping summary:", p["summary"])

    # REST scan
    s = post("/api/scan", {"targets": "127.0.0.1", "ports": "135,139,445,8080", "protocol": "tcp", "timeout": 0.5, "workers": 10, "detect": False})
    print("[OK] /api/scan open_count:", s["open_count"])
    for r in s["results"]:
        print("     ", r["host"], r["port"], r["service"])

    # WS ping
    msgs = asyncio.run(test_ws("ping", {"targets": "127.0.0.1, 127.0.0.2", "count": 1, "timeout": 500, "workers": 4}))
    types = [m["type"] for m in msgs]
    assert types[0] == "start" and types[-1] == "done" and "ping_result" in types
    print("[OK] WS ping 实时推送:", {t: types.count(t) for t in set(types)})

    # WS scan
    msgs = asyncio.run(test_ws("scan", {"targets": "127.0.0.1", "ports": "135,445,8080", "protocol": "tcp", "timeout": 0.5, "workers": 10, "detect": True}))
    types = [m["type"] for m in msgs]
    done = next(m for m in msgs if m["type"] == "done")
    assert types[0] == "start" and "scan_result" in types
    print("[OK] WS scan 实时推送:", {t: types.count(t) for t in set(types)}, "| open:", done["open_count"])
    for m in msgs:
        if m["type"] == "scan_result":
            print("     ", m["data"]["port"], m["data"]["service"], m["data"]["banner"][:50])

    print("\n全部端到端测试通过 ✅")


if __name__ == "__main__":
    main()
