"""NetDiag 桌面应用入口。

内嵌 uvicorn 启动 FastAPI 服务，用 pywebview 打开原生窗口。
支持 --cli 参数以纯终端模式运行服务（方便调试/浏览器访问）。
"""
from __future__ import annotations

import sys
import socket
import threading
import time
import traceback
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _setup_frozen_logging() -> None:
    """打包为 GUI 程序后无控制台，将 stdout/stderr 重定向到日志文件便于排障。"""
    if not getattr(sys, "frozen", False):
        return
    try:
        log_path = Path(sys.executable).resolve().parent / "NetDiag.log"
        log_file = open(log_path, "a", encoding="utf-8")
        log_file.write(f"\n===== NetDiag 启动 {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n")
        log_file.flush()
        sys.stdout = log_file
        sys.stderr = log_file
    except Exception:
        pass


_setup_frozen_logging()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(port: int) -> None:
    import uvicorn
    from app.api import app
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


def run_cli(port: int) -> None:
    print(f"\n  NetDiag 服务已启动: http://127.0.0.1:{port}")
    print("  按 Ctrl+C 停止\n")
    start_server(port)


def run_desktop(port: int) -> None:
    import webview
    server_thread = threading.Thread(target=start_server, args=(port,), daemon=True)
    server_thread.start()
    # 等待服务就绪
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                break
        except OSError:
            time.sleep(0.1)
    window = webview.create_window(
        "NetDiag 网络诊断工具",
        f"http://127.0.0.1:{port}",
        width=1240, height=860, min_size=(900, 600),
        background_color="#F5F7FA",
    )
    webview.start(debug=False)


def main() -> None:
    port = free_port()
    if "--cli" in sys.argv or "--server" in sys.argv:
        run_cli(port)
    else:
        run_desktop(port)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        traceback.print_exc(file=sys.__stderr__) if sys.__stderr__ else None
        raise
