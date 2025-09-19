import os

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

extract_alter("SARIF", "memcached.txt")




# 搜索代码路径

# def code_