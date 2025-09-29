import os
import logging

try:
    from clang import cindex
    from clang.cindex import CursorKind
    libclang_available = True
except ImportError:
    libclang_available = False
    logging.warning("libclang not available. Some features will be disabled.")

PUT_ROOT_PATH = "../PUT"

'''
通过 libclang 对整个翻译单元（file_path传递的源文件和所有头文件）进行分析，查找对目标函数的所有调用。
'''
def find_callers(file_path, function_name):
    """
    找到所有调用目标函数的其他函数
    已初步测试
    :param file_path: 起始文件路径，例如 "memcached/memcached.c"
    :param function_name: 目标函数名称
    :return: list < function_name, source_location >
    """
    # 基于LLVM来实现不要使用基于文本的查找
    # libclang
    if not libclang_available:
        return []
    
    try:
        # 构造完整的文件路径
        # 根据当前工作目录调整PUT路径
        if os.path.exists("../PUT"):
            put_root = "../PUT"
        elif os.path.exists("./PUT"):
            put_root = "./PUT"
        elif os.path.exists("../../PUT"):
            put_root = "../../PUT"
        else:
            put_root = PUT_ROOT_PATH
            
        full_file_path = os.path.join(put_root, file_path)
        
        # 检查文件是否存在
        if not os.path.exists(full_file_path):
            logging.error(f"文件不存在: {full_file_path}")
            return []
        
        # 使用libclang解析文件，它会自动处理包含的头文件
        index = cindex.Index.create()
        
        # 添加包含路径以解决头文件找不到的问题
        args = [
            '-I' + put_root,
            '-I' + os.path.join(put_root, os.path.dirname(file_path)),
            '-I/usr/include',
            '-I/usr/local/include'
        ]
        
        translation_unit = index.parse(full_file_path, args=args)
        
        if not translation_unit:
            logging.error("无法创建 translation unit")
            return []
            
        # 检查诊断信息
        diagnostics = list(translation_unit.diagnostics)
        error_count = 0
        for diag in diagnostics:
            if diag.severity >= 4:  # Error or fatal
                error_count += 1
                logging.warning(f"解析警告/错误: {diag.spelling} (级别: {diag.severity})")
        
        if error_count > 0:
            logging.warning(f"存在 {error_count} 个严重错误，可能影响分析结果")
            
        callers = []
        
        # 遍历AST查找函数调用
        def find_callers_in_cursor(cursor, target_function_name):
            # 如果当前节点是函数调用且名称匹配
            if cursor.kind == CursorKind.CALL_EXPR and cursor.spelling == target_function_name:
                # 获取调用所在的函数
                parent_function = get_parent_function(cursor)
                if parent_function:
                    location = cursor.location
                    if location.file:
                        # 获取调用点的位置
                        file_name = location.file.name
                        if file_name.startswith(os.path.abspath(put_root)):
                            file_name = os.path.relpath(file_name, put_root)
                        caller_info = (parent_function.spelling, f"{file_name}:{location.line}")
                        if caller_info not in callers:
                            callers.append(caller_info)
            
            # 递归遍历子节点
            for child in cursor.get_children():
                find_callers_in_cursor(child, target_function_name)
        
        # 获取包含指定光标的函数
        def get_parent_function(cursor):
            if cursor.kind == CursorKind.FUNCTION_DECL:
                return cursor
            if cursor.semantic_parent:
                return get_parent_function(cursor.semantic_parent)
            return None
        
        find_callers_in_cursor(translation_unit.cursor, function_name)
        return callers
    except Exception as e:
        logging.error(f"Error in find_callers: {e}")
        import traceback
        logging.error(traceback.format_exc())
        return []


def find_callers_in_project(function_name):
    """
    在整个项目中找到所有调用目标函数的其他函数
    :param function_name: 目标函数名称
    :return: list < function_name, source_location >
    """
    if not libclang_available:
        return []