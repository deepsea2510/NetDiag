"""FastAPI 接口层：REST 端点 + WebSocket 实时进度推送。"""
from __future__ import annotations

import asyncio
import uuid
from concurrent.futures import Future
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .utils import expand_targets, expand_ports, TargetParseError
from .paths import static_dir
from . import ping_engine, port_scanner, netifaces, device_id

app = FastAPI(title="NetDiag 网络诊断工具", version="1.0")
STATIC_DIR = static_dir()
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


# ---------- 请求模型 ----------
class PingRequest(BaseModel):
    targets: str
    count: int = Field(default=4, ge=1, le=20)
    timeout: int = Field(default=1000, ge=100, le=10000)
    workers: int = Field(default=32, ge=1, le=256)


class ScanRequest(BaseModel):
    targets: str
    ports: str
    protocol: str = Field(default="tcp", pattern="^(tcp|udp)$")
    timeout: float = Field(default=0.6, ge=0.1, le=10)
    workers: int = Field(default=100, ge=1, le=500)
    detect: bool = True


# ---------- REST 同步接口 ----------
@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "NetDiag"}


@app.get("/api/netifaces")
def api_netifaces():
    """返回本机网卡网段（供前端一键填入）。"""
    try:
        return {"networks": [n.to_dict() for n in netifaces.local_networks()]}
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=500, content={"error": str(exc)})


@app.post("/api/ping")
def api_ping(req: PingRequest):
    try:
        hosts = expand_targets(req.targets)
    except TargetParseError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    results = ping_engine.ping_batch(hosts, req.count, req.timeout, req.workers)
    return {
        "targets": len(hosts),
        "summary": ping_engine.summarize(results),
        "results": [r.to_dict() for r in results],
    }


@app.post("/api/scan")
def api_scan(req: ScanRequest):
    try:
        hosts = expand_targets(req.targets)
        ports = expand_ports(req.ports)
    except TargetParseError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    results = port_scanner.scan(
        hosts, ports, req.protocol, req.timeout, req.workers, req.detect
    )
    return {
        "hosts": len(hosts), "ports": len(ports), "protocol": req.protocol,
        "open_count": len(results),
        "results": [r.to_dict() for r in results],
    }


# ---------- 任务管理（支持停止） ----------
class _TaskState:
    """单个正在运行的任务状态。cancelled 由 stop 指令置位，引擎轮询该标志。"""

    def __init__(self, task_id: str, kind: str) -> None:
        self.id = task_id
        self.kind = kind
        self.cancelled = False
        self.async_task: asyncio.Task | None = None
        self.future: Future | None = None

    def is_cancelled(self) -> bool:
        return self.cancelled


# key: websocket 连接对象 -> 当前任务
_active_tasks: dict[WebSocket, _TaskState] = {}


def _cancel_active(ws: WebSocket) -> bool:
    state = _active_tasks.get(ws)
    if not state:
        return False
    state.cancelled = True
    # 尝试取消底层 executor future（若已提交）
    return True


async def _ws_send(ws: WebSocket, payload: dict) -> None:
    try:
        await ws.send_json(payload)
    except Exception:  # noqa: BLE001  # 连接已断开时忽略
        pass


async def handle_ping_ws(ws: WebSocket, data: dict, state: _TaskState) -> None:
    req = PingRequest(**data)
    hosts = expand_targets(req.targets)
    total = len(hosts)
    await _ws_send(ws, {"type": "start", "task": "ping", "total": total, "task_id": state.id})

    loop = asyncio.get_event_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def progress(res, done, count):
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {"type": "ping_result", "data": res.to_dict(), "done": done, "total": count},
        )

    future: Future = loop.run_in_executor(
        None,
        lambda: ping_engine.ping_batch(
            hosts, req.count, req.timeout, req.workers, progress, state.is_cancelled
        ),
    )
    state.future = future

    results: list = []
    while not future.done() or not queue.empty():
        try:
            msg = await asyncio.wait_for(queue.get(), timeout=0.1)
            await _ws_send(ws, msg)
            if msg["type"] == "ping_result":
                results.append(msg["data"])
        except asyncio.TimeoutError:
            continue
    results = await future
    summary = ping_engine.summarize(results)
    # v10.14：终端识别。只读本机邻居表 + ICMP 回包 TTL，不发任何探测包；
    # 放到线程里跑，避免 SendARP 把事件循环卡住。
    if data.get("identify", True):
        try:
            nets = netifaces.local_networks()
            await asyncio.to_thread(device_id.annotate, results, nets)
        except Exception:                            # noqa: BLE001
            pass
    # 若已被新任务取代，不再推送旧任务的收尾消息，避免干扰前端
    if _active_tasks.get(ws) is state:
        await _ws_send(ws, {
            "type": "done", "task": "ping", "task_id": state.id,
            "summary": summary, "cancelled": state.cancelled,
            "results": [r.to_dict() for r in results],   # 含识别结果，供前端重渲染
            "message": (f"已停止，完成 {len(results)}/{total} 个目标" if state.cancelled else None),
        })


async def handle_scan_ws(ws: WebSocket, data: dict, state: _TaskState) -> None:
    req = ScanRequest(**data)
    hosts = expand_targets(req.targets)
    ports = expand_ports(req.ports)
    total = len(hosts) * len(ports)
    await _ws_send(ws, {
        "type": "start", "task": "scan", "total": total,
        "hosts": len(hosts), "ports": len(ports), "task_id": state.id,
    })

    loop = asyncio.get_event_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def progress(res, done, count):
        msg_type = "scan_result" if res.state != "closed" else "progress"
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {"type": msg_type, "data": res.to_dict(), "done": done, "total": count},
        )

    future: Future = loop.run_in_executor(
        None,
        lambda: port_scanner.scan(
            hosts, ports, req.protocol, req.timeout, req.workers,
            req.detect, progress, state.is_cancelled,
        ),
    )
    state.future = future

    # 进度推送用独立协程，主循环保持可接收 stop 指令
    async def pump():
        while not future.done() or not queue.empty():
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=0.1)
                await _ws_send(ws, msg)
            except asyncio.TimeoutError:
                continue

    await pump()
    results = await future
    if _active_tasks.get(ws) is state:
        await _ws_send(ws, {
            "type": "done", "task": "scan", "task_id": state.id,
            "open_count": len(results), "cancelled": state.cancelled,
            "message": (f"已停止，收集到 {len(results)} 项结果" if state.cancelled else None),
        })


async def _run_task(ws: WebSocket, data: dict, state: _TaskState) -> None:
    try:
        if state.kind == "ping":
            await handle_ping_ws(ws, data, state)
        else:
            await handle_scan_ws(ws, data, state)
    except TargetParseError as exc:
        await _ws_send(ws, {"type": "error", "message": str(exc)})
    except Exception as exc:  # noqa: BLE001
        await _ws_send(ws, {"type": "error", "message": str(exc)})
    finally:
        if _active_tasks.get(ws) is state:
            _active_tasks.pop(ws, None)


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    try:
        while True:
            raw = await ws.receive_json()
            action = raw.get("action")

            if action == "stop":
                if _cancel_active(ws):
                    await _ws_send(ws, {"type": "stopping", "message": "正在停止..."})
                else:
                    await _ws_send(ws, {"type": "error", "message": "当前没有运行中的任务"})
                continue

            if action in ("ping", "scan"):
                # 若已有任务在跑，先取消它
                _cancel_active(ws)
                task_id = uuid.uuid4().hex[:8]
                state = _TaskState(task_id, action)
                _active_tasks[ws] = state
                state.async_task = asyncio.create_task(_run_task(ws, raw, state))
                continue

            await _ws_send(ws, {"type": "error", "message": f"未知操作: {action}"})
    except WebSocketDisconnect:
        _cancel_active(ws)
        _active_tasks.pop(ws, None)
