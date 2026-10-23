"""Entry point: python main.py  (or python.exe main.py on Windows)

Starts FastAPI backend with uvicorn on 0.0.0.0:8001.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> None:
    try:
        import uvicorn
    except ImportError:
        print("uvicorn نصب نیست. اجرا کنید: pip install -r requirements.txt", file=sys.stderr)
        raise SystemExit(1) from None

    host = "0.0.0.0"
    port = 8001
    print(f"Starting backend: http://{host}:{port}  (health: http://127.0.0.1:{port}/health)")
    uvicorn.run(
        "backend.main:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
