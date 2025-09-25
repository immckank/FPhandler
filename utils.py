import os
import networkx as nx
import pydot

PUT_ROOT_PATH = "PUT"

# 找到指定项目中指定文件名的路径
def find_file_path(project_name, file_name):
    for root, dirs, files in os.walk(os.path.join(PUT_ROOT_PATH, project_name)):
        if file_name in files:
            # 路径中不包含PUT_ROOT_PATH
            full_path = os.path.join(root, file_name)
            return full_path.replace(PUT_ROOT_PATH, "").replace("\\", "/").lstrip("/")
    return None

# 根据指定source_location找到对应的代码行
def find_code_line(source_location):
    file_path = source_location.split(":")[0]
    # replace \ with /
    file_path = file_path.replace("\\", "/").lstrip("/")
    file_path = os.path.join(PUT_ROOT_PATH, file_path).replace("\\", "/").lstrip("/")
    print(file_path)
    if not file_path:
        return None
    with open(file_path, 'r') as f:
        lines = f.readlines()
        line_number = int(source_location.split(":")[1]) - 1
        if line_number < 0 or line_number >= len(lines):
            return None
        return lines[line_number].strip()

# 提取赋值表达式的左值变量名
def extract_lhs_variable(assignment):
    assignment = assignment.strip()
    if '=' in assignment:
        lhs = assignment.split('=')[0].strip()
        # 变量名通常是LHS（左手边）的最后一个词
        parts = lhs.split()
        if not parts:
            return None
        # 移除所有前缀的星号和后缀的方括号
        variable_name = parts[-1].lstrip('*').rstrip('[]')
        return variable_name
    return None

# 提取SARIF文件中的alter部分
def extract_alter(sarif_path, sarif_file_name):
    seperator = "#####"
    line_alter = 0

    # txt格式文件
    with open(os.path.join(sarif_path, sarif_file_name), 'r') as f:
        # 统计行总数
        # 找到最后一个以seperator开头的行
        line_total = 0
        for line in f:
            line_total += 1
            if line.startswith(seperator):
                line_alter = line_total
    # 从line_alter行开始提取到文件末尾
    with open(os.path.join(sarif_path, sarif_file_name), 'r') as f:
        extracted_lines = f.readlines()[line_alter:]
    # 保存到文件
    with open(os.path.join(sarif_path, sarif_file_name.replace('.txt', '_alter.txt')), 'w') as f:
        f.writelines(extracted_lines)
    return extracted_lines

# 读取 dot 文件为 networkx 有向图
def load_dot_to_nx(dot_path):
    graphs = pydot.graph_from_dot_file(dot_path)
    p = graphs[0]
    G = nx.DiGraph()
    # 解析节点
    for n in p.get_nodes():
        name = n.get_name().strip('"')
        attrs = n.get_attributes() or {}
        # 常见属性: label, file, line, func 等
        G.add_node(name, **attrs)
    # 解析边
    for e in p.get_edges():
        src = e.get_source().strip('"')
        dst = e.get_destination().strip('"')
        attrs = e.get_attributes() or {}
        G.add_edge(src, dst, **attrs)
    return G

G = load_dot_to_nx("GRAPH/icfg_initial.dot")
