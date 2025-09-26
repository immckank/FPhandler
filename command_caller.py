import os
import subprocess


# 尝试借助此文件唤起SVF中 graph-reader 命令行工具的相关方法
# exp1
# graph-reader --find-function-body="stats_prefix.c:118" memcached.bc


def setup_env(setupbash_path="../SVFmemplus/setup.sh"):
    # source setup.sh, 然后打印出所有环境变量
    command = f"bash -c 'source {setupbash_path} && env'"
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    for line in proc.stdout:
        (key, _, value) = line.decode("utf-8").partition("=")
        # 将环境变量设置到当前Python进程
        os.environ[key] = value.strip()
    proc.communicate()

def call_graph_reader(dot_path):
    # 调用 graph-reader 命令行工具
    result = subprocess.run(['graph-reader', dot_path], capture_output=True, text=True)
    if result.returncode != 0:
        print("Error calling graph-reader:", result.stderr)
        return None
    return result.stdout

def test_graph_reader():
    # 执行graph-reader --find-function-body="stats_prefix.c:118" memcached.bc
    dot_path = "memcached.bc"
    # 注意：这里的路径需要根据你的项目结构调整，我假设 memcached.bc 在 PUT 目录下
    command = f'graph-reader -find-function-body="stats_prefix.c:118" PUT/{dot_path}'
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    if result.returncode != 0:
        print("Error calling graph-reader:", result.stderr)
        return None
    return result.stdout


if __name__ == '__main__':
    setup_env()
    print(test_graph_reader())