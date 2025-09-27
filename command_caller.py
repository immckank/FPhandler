import os
import json
import subprocess


# 尝试借助此文件唤起SVF中 graph-reader 命令行工具的相关方法
# exp1
# graph-reader --find-function-body="stats_prefix.c:118" memcached.bc

class CommandCaller:
    def __init__(self, setupbash_path="../SVFmemplus/setup.sh"):
        self.setupbash_path = setupbash_path
        self.setup_env()

    def setup_env(self):
        # source setup.sh
        command = f"bash -c 'source {self.setupbash_path} && env'"
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        for line in proc.stdout:
            (key, _, value) = line.decode("utf-8").partition("=")
            os.environ[key] = value.strip()
        proc.communicate()

    def call_graph_reader(self, arg_type, arg_value, dot_path):
        # 调用 graph-reader 命令行工具
        command = ['graph-reader', f'-{arg_type}', arg_value, dot_path]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error calling graph-reader with command: {' '.join(command)}", result.stderr)
            return None
        return result.stdout

# def test_graph_reader():
#     # 执行graph-reader -find-function-body="stats_prefix.c:118" memcached.bc
#     dot_path = "memcached.bc"
#     command = f'graph-reader -find-function-body="stats_prefix.c:118" PUT/{dot_path}'
#     result = subprocess.run(command, capture_output=True, text=True)
#     if result.returncode != 0:
#         print("Error calling graph-reader:", result.stderr)
#         return None
#     return result.stdout


if __name__ == '__main__':
    caller = CommandCaller()
    res = caller.call_graph_reader("find-function-body", "stats_prefix.c:118", "PUT/memcached.bc")
    print(res)
    # read res as json
    res_json = json.loads(res)
    print(res_json["function_name"])
    