import os
import json
import subprocess
import atexit
import time
import shlex
import shutil
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_DEFAULT_SETUP_SH = _SCRIPT_DIR.parent / "SVFmemplus" / "setup.sh"


class CommandCaller:
    _instance = None
    _process = None
    _active_bitcode_path = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(CommandCaller, cls).__new__(cls)
        return cls._instance

    def __init__(self, setupbash_path=None, startup_timeout_sec: float = 12120.0):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        if setupbash_path is None:
            p = _DEFAULT_SETUP_SH
        else:
            p = Path(setupbash_path)
            if not p.is_absolute():
                p = (_SCRIPT_DIR / p).resolve()
            else:
                p = p.resolve()
        self.setupbash_path = str(p)
        self.startup_timeout_sec = startup_timeout_sec

        # 1) 在 setup.sh 所在目录下 source（与手动 cd 到 SVFmemplus 再 source 一致），并合并进当前进程环境
        self._setup_env()

        # graph-reader 在 ensure_bitcode_for_sar 或首次 send_query 时再启动（支持按 SAR 切换 .bc）

        # 2) register cleanup
        atexit.register(self._cleanup_process)

    def _setup_env(self):
        setup = Path(self.setupbash_path)
        if not setup.is_file():
            raise FileNotFoundError(
                f"未找到 setup.sh: {setup}（请确认 SVFmemplus 路径或传入 setupbash_path）"
            )
        setup_dir = setup.parent
        inner = (
            f"cd -- {shlex.quote(str(setup_dir))} && "
            f"source ./{shlex.quote(setup.name)} && env"
        )
        proc = subprocess.run(
            ["bash", "-lc", inner],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"source setup.sh 失败 (exit {proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
            )
        for line in proc.stdout.splitlines():
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            if key:
                os.environ[key] = value
        if not shutil.which("graph-reader", path=os.environ.get("PATH", "")):
            import config as _cfg

            if not (
                os.environ.get("SVF_DOCKER_IMAGE")
                or getattr(_cfg, "SVF_DOCKER_IMAGE", None)
                or getattr(_cfg, "GRAPH_READER_DOCKER_IMAGE", None)
                or os.environ.get("GRAPH_READER_DOCKER_IMAGE")
            ):
                raise FileNotFoundError(
                    "PATH 中仍找不到 graph-reader：请先在 SVFmemplus 下编译生成 "
                    "Release-build/bin/graph-reader（或 Debug），并确认 setup.sh 能正确 export PATH；"
                    "或在全局 config.env 设置 svf_docker_image。"
                )

    def _graph_reader_docker_image(self):
        import config as _cfg

        return (
            os.environ.get("SVF_DOCKER_IMAGE")
            or getattr(_cfg, "SVF_DOCKER_IMAGE", None)
            or getattr(_cfg, "GRAPH_READER_DOCKER_IMAGE", None)
            or os.environ.get("GRAPH_READER_DOCKER_IMAGE")
            or ""
        ).strip()

    def _graph_reader_command(self, bitcode_path: str):
        image = self._graph_reader_docker_image()
        if not image:
            return ["graph-reader", "-stat=false", bitcode_path]

        svf_dir = Path(self.setupbash_path).parent.resolve()
        bc_path = Path(bitcode_path).resolve()
        inner = (
            "source ./setup.sh Release && "
            "export PATH=/SVFmemplus/Release-build/bin:$PATH && "
            "export LD_LIBRARY_PATH=/SVFmemplus/z3.obj/bin:${LD_LIBRARY_PATH:-} && "
            "if [[ ! -e /usr/lib/libz3.so.4 && -e /SVFmemplus/z3.obj/bin/libz3.so ]]; then "
            "ln -sf /SVFmemplus/z3.obj/bin/libz3.so /usr/lib/libz3.so.4; fi && "
            "exec graph-reader -stat=false /data/target.bc"
        )
        return [
            "docker",
            "run",
            "-i",
            "--rm",
            "-v",
            f"{svf_dir}:/SVFmemplus",
            "-v",
            f"{bc_path}:/data/target.bc:ro",
            "-w",
            "/SVFmemplus",
            image,
            "bash",
            "-lc",
            inner,
        ]

    def _start_graph_reader_process_with_path(self, bitcode_path: str):
        if CommandCaller._process is not None:
            if CommandCaller._process.poll() is None:
                return
            CommandCaller._process = None
        bitcode_path = os.path.abspath(os.path.expanduser(bitcode_path))
        if not os.path.isfile(bitcode_path):
            raise FileNotFoundError(f"bitcode 文件不存在: {bitcode_path}")

        command = self._graph_reader_command(bitcode_path)
        CommandCaller._process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=os.environ,
        )

    def ensure_bitcode_for_sar(self, sar_path: str) -> str:
        """按 SAR 解析 .bc；与当前 graph-reader 所用路径不同时会重启子进程。"""
        from utils import resolve_bitcode_path_for_sar

        path = os.path.abspath(resolve_bitcode_path_for_sar(sar_path))
        if not os.path.isfile(path):
            raise FileNotFoundError(
                f"与 SAR 同名的 bitcode 不存在: {path}（SAR: {sar_path}）"
            )
        if (
            CommandCaller._active_bitcode_path == path
            and CommandCaller._process is not None
            and CommandCaller._process.poll() is None
        ):
            return path
        self._cleanup_process()
        CommandCaller._active_bitcode_path = path
        self._start_graph_reader_process_with_path(path)
        self._wait_until_ready()
        return path

    def _wait_until_ready(self):
        if CommandCaller._process is None:
            raise RuntimeError("GraphReader process not started")
        start_time = time.time()
        while True:
            if (time.time() - start_time) > self.startup_timeout_sec:
                raise TimeoutError("Timed out waiting for GraphReader ready signal")
            line = CommandCaller._process.stdout.readline()
            if not line:
                # process might have died
                if CommandCaller._process.poll() is not None:
                    raise RuntimeError("GraphReader process exited before ready")
                continue
            line_stripped = line.strip()
            if not line_stripped:
                continue
            # read line from graph-reader
            try:
                msg = json.loads(line_stripped)
                if isinstance(msg, dict) and msg.get("ready") is True:
                    return
            except json.JSONDecodeError:
                # Not a JSON line we care about; keep reading
                continue

    def send_query(self, query_json: dict) -> str:
        if CommandCaller._process is None or CommandCaller._process.poll() is not None:
            bp = CommandCaller._active_bitcode_path
            if not bp:
                from config import BITCODE_PATH as _cfg_bp

                if _cfg_bp and str(_cfg_bp).strip():
                    bp = os.path.abspath(os.path.expanduser(str(_cfg_bp).strip()))
            if not bp:
                return json.dumps(
                    {
                        "error": "GraphReader process not available: call "
                        "ensure_bitcode_for_sar(sar_path) first, or set BITCODE_PATH in config."
                    }
                )
            CommandCaller._active_bitcode_path = bp
            self._start_graph_reader_process_with_path(bp)
            self._wait_until_ready()
            if CommandCaller._process is None or CommandCaller._process.poll() is not None:
                return json.dumps({"error": "GraphReader process not available."})

        query_str = json.dumps(query_json) + '\n'
        CommandCaller._process.stdin.write(query_str)
        CommandCaller._process.stdin.flush()

        response_line = CommandCaller._process.stdout.readline()
        # # Optionally read a stderr line if present (non-blocking would need threads; keep simple)
        # try:
        #     if CommandCaller._process.stderr and not CommandCaller._process.stderr.closed:
        #         err_line = CommandCaller._process.stderr.readline()
        #         if err_line:
        #             pass
        # except Exception:
        #     pass
        
        # print(f"response_line: {response_line}")
        return response_line

    def _cleanup_process(self):
        proc = CommandCaller._process
        if proc is None:
            return
        if proc.poll() is None:
            try:
                proc.stdin.write(json.dumps({"command": "exit"}) + "\n")
                proc.stdin.flush()
                proc.stdin.close()
                proc.wait(timeout=5)
                if proc.poll() is None:
                    proc.terminate()
            except Exception:
                pass
        CommandCaller._process = None

if __name__ == '__main__':
    # Simple manual test using the commands from options.txt (1-8)
    caller = CommandCaller()

    tests = [
        {"command": "find-function-body-by-name", "name": "X509V3_EXT_add_alias"},
        {"command": "find-function-body-by-location", "fl": "bf_enc.c", "ln": 30},
        {"command": "find-all-function-call-sites", "name": "TIFFCreateDirectory"},
        {"command": "find-all-function-callees", "name": "ssl_module_init"},
    ]

    for t in tests:
        print(f"sending query: {t}")
        resp = caller.send_query(t)
        print(resp.strip())

    # exit the persistent process
    caller._cleanup_process()

# if __name__ == '__main__':
#     caller = CommandCaller()
#     res = caller.call_graph_reader("find-function-body", "stats_prefix.c:118", "PUT/memcached.bc")
#     print(res)
#     # read res as json
#     res_json = json.loads(res)
#     print(res_json["function_name"])
#     # Example usage:
#     # Ensure config.py BITCODE_PATH points to the correct .bc
#     # And your C++ graph-reader executable is compiled and in PATH
    
#     # First call initializes the singleton and starts the C++ process
#     caller1 = CommandCaller()
    
#     # Subsequent calls return the same instance
#     caller2 = CommandCaller()
#     assert caller1 is caller2

#     # Example query: find function body
#     query = {
#         "command": "find-function-body",
#         "location": "stats_prefix.c:118" # Example location, adjust as needed
#     }
#     response = caller1.send_query(query)
#     print(f"Response for find-function-body: {response.strip()}")
    
#     if response:
#         try:
#             res_json = json.loads(response)
#             if "error" in res_json and res_json["error"]:
#                 print(f"Error from C++: {res_json['error']}")
#             else:
#                 print(f"Function name: {res_json.get('function_name', 'N/A')}")
#         except json.JSONDecodeError:
#             print(f"Failed to decode JSON response: {response}")

#     # Example query: find call sites
#     query_call_sites = {
#         "command": "find-call-sites",
#         "function_name": "stats_prefix_record_get" # Example function name
#     }
#     response_call_sites = caller1.send_query(query_call_sites)
#     print(f"Response for find-call-sites: {response_call_sites.strip()}")

#     # The atexit handler will automatically send the "exit" command and terminate the C++ process
#     # when the Python script finishes.
    