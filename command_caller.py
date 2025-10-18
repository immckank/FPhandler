import os
import json
import subprocess

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
    
    def call_graph_reader_with_args(self, *args):
        """
        Calls the graph-reader command-line tool with a variable number of arguments.
        This is useful for commands with complex parameter structures.
        """
        # 添加一个默认的选项-stat=false来避免打印不相关信息
        command = ['graph-reader', '-stat=false'] + list(args)
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error calling graph-reader with command: {' '.join(command)}", result.stderr)
            return None
        return result.stdout

if __name__ == '__main__':
    caller = CommandCaller()
    res = caller.call_graph_reader("find-function-body", "stats_prefix.c:118", "PUT/memcached.bc")
    print(res)
    # read res as json
    res_json = json.loads(res)
    print(res_json["function_name"])
    