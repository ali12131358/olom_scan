// Vite dev-server plugin: loopback-only control endpoints to start/stop/status
// the FastAPI backend (uvicorn) as a child process. Dev-only: `vite build`
// never includes middleware. The browser cannot spawn processes by itself,
// so this plugin performs it on behalf of the local page.
import {defineConfig} from "vite";
import react from "@vitejs/plugin-react";
import http from "node:http";
import {spawn} from "node:child_process";
import {existsSync} from "node:fs";
import path from "node:path";
import {delimiter} from "node:path";
import {fileURLToPath} from "node:url";

const BACKEND_PORT = 8001;
const API_URL = `http://127.0.0.1:${BACKEND_PORT}`;
const MAX_LOG_CHARS = 8000; // bounded log buffer per stream

function projectRoot() {
  // frontend/vite.config.js -> project root
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}


function findUvicornExecutable() {
  // Resolve uvicorn CLI, or fall back to `python -m uvicorn`.
  const isWindows = process.platform === "win32";
  const guidance = "Install backend dependencies with `pip install -r requirements.txt`, or set PYTHON_EXECUTABLE.";
  const pythonNames = isWindows
    ? ["python.exe", "python3.exe", "py.exe"]
    : ["python3", "python"];

  function resolveFromPath(name) {
    for (const dir of (process.env.PATH || "").split(delimiter)) {
      if (!dir) continue;
      const candidate = path.join(dir, name);
      if (existsSync(candidate)) return candidate;
    }
    return "";
  }

  if (process.env.PYTHON_EXECUTABLE) {
    const configuredPython = process.env.PYTHON_EXECUTABLE;
    let pythonPath = "";
    if (path.isAbsolute(configuredPython)) {
      if (existsSync(configuredPython)) pythonPath = configuredPython;
    } else {
      pythonPath = resolveFromPath(configuredPython);
    }
    if (!pythonPath) return {error: `PYTHON_EXECUTABLE was not found: ${configuredPython}. ${guidance}`};
    const pythonDir = path.dirname(pythonPath);
    const uvicornPath = path.join(pythonDir, isWindows ? "uvicorn.exe" : "uvicorn");
    if (existsSync(uvicornPath)) return {executable: uvicornPath, argsPrefix: []};
    return {executable: pythonPath, argsPrefix: ["-m", "uvicorn"]};
  }

  const uvicornName = isWindows ? "uvicorn.exe" : "uvicorn";
  const uvicornPath = resolveFromPath(uvicornName);
  if (uvicornPath) return {executable: uvicornPath, argsPrefix: []};

  for (const name of pythonNames) {
    const py = resolveFromPath(name);
    if (py) return {executable: py, argsPrefix: ["-m", "uvicorn"]};
  }
  return {error: `Uvicorn/Python was not found on PATH. ${guidance}`};
}

function trimLog(buffer) {
  const text = buffer.join("");
  return text.length > MAX_LOG_CHARS ? text.slice(text.length - MAX_LOG_CHARS) : text;
}

function loopbackOnly(req) {
  const addr = req.socket?.remoteAddress || "";
  if (addr === "127.0.0.1" || addr === "::1" || addr === "::ffff:127.0.0.1") return true;
  // Also accept plain IPv6 loopback variants like ::ffff:7f00:1
  return addr === "::ffff:7f00:1";
}

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.statusCode = code;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(body);
}

function healthCheck(timeoutMs = 1200) {
  return new Promise((resolve) => {
    const req = http.get(API_URL + "/health", {timeout: timeoutMs}, (res) => {
      res.resume();
      resolve(res.statusCode >= 200 && res.statusCode < 500);
    });
    req.on("timeout", () => { req.destroy(); resolve(false); });
    req.on("error", () => resolve(false));
  });
}

export function localBackendPlugin() {
  let child = null; // managed uvicorn child process
  let starting = false;
  let stopping = false;
  let lastError = null;
  let stdoutChunks = [];
  let stderrChunks = [];
  let exitInfo = null; // {code, signal}

  const state = () => ({
    managed_pid: child && child.exitCode === null && !child.killed ? child.pid : null,
    starting,
    stopping,
    last_error: lastError,
    last_exit: exitInfo,
    api_url: API_URL,
  });

  function attach(childProc) {
    childProc.stdout?.on("data", (d) => {
      stdoutChunks.push(String(d));
      if (stdoutChunks.length > 200) stdoutChunks = stdoutChunks.slice(-100);
    });
    childProc.stderr?.on("data", (d) => {
      stderrChunks.push(String(d));
      if (stderrChunks.length > 200) stderrChunks = stderrChunks.slice(-100);
    });
    childProc.on("error", (err) => {
      lastError = "spawn error: " + (err && err.message ? err.message : String(err));
      starting = false;
    });
    childProc.on("exit", (code, signal) => {
      exitInfo = {code, signal, at: new Date().toISOString()};
      child = null;
      starting = false;
    });
  }

  async function startBackend() {
    if (starting || stopping) return {ok: false, status: "busy", ...state()};
    if (child && child.exitCode === null && !child.killed) {
      return {ok: true, status: "already_running", ...state()};
    }
    if (await healthCheck()) {
      return {ok: true, status: "external_running", ...state()};
    }
    starting = true;
    lastError = null;
    exitInfo = null;
    stdoutChunks = [];
    stderrChunks = [];
    const root = projectRoot();
    const resolved = findUvicornExecutable();
    if (resolved.error) {
      starting = false;
      lastError = resolved.error;
      return {ok: false, status: "error", error: lastError, ...state()};
    }
    const args = [...(resolved.argsPrefix || []), "backend.main:app", "--host", "0.0.0.0", "--port", "8001"];
    try {
      const spawned = spawn(resolved.executable, args, {
        cwd: root,
        shell: false,
        env: {...process.env, PYTHONUNBUFFERED: "1"},
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
      child = spawned;
      attach(spawned);
    } catch (err) {
      starting = false;
      child = null;
      lastError = "spawn failed: " + (err && err.message ? err.message : String(err));
      return {ok: false, status: "error", error: lastError, ...state()};
    }
    // wait briefly for either health or failure
    const deadline = Date.now() + 12000;
    while (Date.now() < deadline) {
      if (child && child.exitCode !== null) {
        starting = false;
        return {ok: false, status: "exited", error: lastError || `backend exited with code ${child.exitCode}`, ...state()};
      }
      if (await healthCheck(600)) {
        starting = false;
        return {ok: true, status: "started", ...state()};
      }
      await new Promise((r) => setTimeout(r, 300));
    }
    // timed out waiting: keep child running but report not confirmed
    starting = false;
    return {ok: false, status: "timeout", error: "backend did not answer /health in time", ...state()};
  }

  async function stopBackend() {
    if (starting) return {ok: false, status: "busy", ...state()};
    if (!child || child.exitCode !== null || child.killed) {
      child = null;
      return {ok: true, status: "not_running", ...state()};
    }
    stopping = true;
    const target = child;
    target.kill(process.platform === "win32" ? undefined : "SIGTERM");
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline && target.exitCode === null) {
      await new Promise((r) => setTimeout(r, 150));
    }
    if (target.exitCode === null) {
      try { target.kill("SIGKILL"); } catch {}
      await new Promise((r) => setTimeout(r, 400));
    }
    stopping = false;
    child = null;
    return {ok: true, status: "stopped", ...state()};
  }

  async function statusBackend() {
    const external = await healthCheck(800);
    const managed = child && child.exitCode === null && !child.killed ? child.pid : null;
    return {
      status: external ? "running" : managed ? "starting" : "stopped",
      running: external,
      source: external ? (managed ? "managed" : "external") : "none",
      managed_pid: managed,
      logs: {stdout: trimLog(stdoutChunks), stderr: trimLog(stderrChunks)},
      ...state(),
    };
  }

  return {
    name: "local-backend-controller",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        const url = (req.url || "").split("?")[0];
        if (!url.startsWith("/__local_backend/")) return next();
        if (req.method === "POST" && url === "/__local_backend/start") {
          return sendJson(res, 200, await startBackend());
        }
        if (req.method === "POST" && url === "/__local_backend/stop") {
          return sendJson(res, 200, await stopBackend());
        }
        if (req.method === "GET" && url === "/__local_backend/status") {
          return sendJson(res, 200, await statusBackend());
        }
        return sendJson(res, 404, {ok: false, error: "unknown endpoint"});
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), localBackendPlugin()],
  server: {
    port: 5001,
    host: true, // 0.0.0.0 — accessible via NAT / public IP
    proxy: {
      // Single public port (5001): browser talks to Vite; Vite forwards API to local FastAPI
      "/scans": { target: "http://127.0.0.1:8001", changeOrigin: true },
      "/devices": { target: "http://127.0.0.1:8001", changeOrigin: true },
      "/health": { target: "http://127.0.0.1:8001", changeOrigin: true },
      "/api": { target: "http://127.0.0.1:8001", changeOrigin: true },
      "/reports": { target: "http://127.0.0.1:8001", changeOrigin: true },
    },
  },
});
