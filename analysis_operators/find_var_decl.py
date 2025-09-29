import os
import logging

try:
    from clang import cindex
    from clang.cindex import CursorKind
    libclang_available = True
except ImportError:
    libclang_available = False
    logging.warning("libclang not available. Some features will be disabled.")

# 使用基于项目根目录的绝对路径
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUT_ROOT_PATH = os.path.join(PROJECT_ROOT, "PUT")

def find_var_decl(source_location, var_name):
    """
    找到变量声明的位置
    已初步测试！
    return: source_location: 'memcached/slab_automove.c:37'
    """
    # 基于LLVM来实现不要使用基于文本的查找
    # 基于LLVM的实现比基于文本的查找方法更加精确，因为它基于编译器级别的代码分析，能够准确识别变量声明的位置，而不会被注释、字符串或其他文本中的相似内容干扰。
    # libclang
    if not libclang_available:
        return None
    
    try:
        # 解析source_location获取文件路径
        file_path = source_location.split(":")[0]
        
        # 构造完整的文件路径
        full_file_path = os.path.join(PUT_ROOT_PATH, file_path)
        logging.info(f"Attempting to parse file: {full_file_path}")
        logging.info(f"File exists: {os.path.exists(full_file_path)}")
        logging.info(f"Current working directory: {os.getcwd()}")
        logging.info(f"Absolute path: {os.path.abspath(full_file_path)}")
        
        # 检查文件是否真的存在
        if not os.path.exists(full_file_path):
            logging.error(f"File does not exist: {full_file_path}")
            return None
        
        # 使用libclang解析文件，它会自动处理包含的头文件
        index = cindex.Index.create()
        # 传递适当的解析选项，确保包含的文件也被解析
        logging.info(f"Parsing with include path: {PUT_ROOT_PATH}")
        logging.info(f"Full args: {['-I' + PUT_ROOT_PATH]}")
        
        # 尝试添加更多编译参数以提高解析成功率
        args = ['-I' + PUT_ROOT_PATH]
        translation_unit = index.parse(full_file_path, args=args)
        
        if not translation_unit:
            logging.error("Failed to create translation unit")
            return None
            
        # 在整个翻译单元中查找变量声明（包括包含的头文件）
        def find_variable_decl(cursor, var_name):
            # 支持多种声明类型
            supported_kinds = [
                CursorKind.VAR_DECL,        # 变量声明
                CursorKind.STRUCT_DECL,     # 结构体声明
                CursorKind.TYPEDEF_DECL,    # typedef声明
                CursorKind.FUNCTION_DECL,   # 函数声明
                CursorKind.ENUM_DECL,       # 枚举声明
                CursorKind.ENUM_CONSTANT_DECL,  # 枚举常量声明
                CursorKind.MACRO_DEFINITION     # 宏定义
            ]
            
            if cursor.kind in supported_kinds and cursor.spelling == var_name:
                location = cursor.location
                if location.file:
                    # 返回格式: 'filename:line_number'
                    # 使用实际的文件名而不是原始的file_path
                    file_name = location.file.name
                    # 移除PUT_ROOT_PATH前缀以保持一致性
                    if file_name.startswith(os.path.abspath(PUT_ROOT_PATH)):
                        file_name = os.path.relpath(file_name, PUT_ROOT_PATH)
                    return f"{file_name}:{location.line}"
            
            # 递归遍历子节点
            for child in cursor.get_children():
                result = find_variable_decl(child, var_name)
                if result:
                    return result
            return None
        
        return find_variable_decl(translation_unit.cursor, var_name)
    except Exception as e:
        logging.error(f"Error in find_var_decl: {e}", exc_info=True)
        return None