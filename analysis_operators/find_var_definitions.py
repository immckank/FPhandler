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

def find_var_definitions(source_location, var_name):
    """
    找到指定变量所有被定义的位置（只返回实际分配内存的定义位置，而不是extern声明）
    已初步测试
    return: list < source_location >
    """
    # 基于LLVM来实现不要使用基于文本的查找
    # libclang
    if not libclang_available:
        return []
    
    try:
        # 解析source_location获取文件路径
        file_path = source_location.split(":")[0]
        
        # 构造完整的文件路径
        full_file_path = os.path.join(PUT_ROOT_PATH, file_path)
        
        # 检查文件是否存在
        if not os.path.exists(full_file_path):
            logging.error(f"文件不存在: {full_file_path}")
            return []
        
        # 使用libclang解析文件，它会自动处理包含的头文件
        index = cindex.Index.create()
        # 传递适当的解析选项，确保包含的文件也被解析
        args = ['-I' + PUT_ROOT_PATH]
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
            
        # 在整个翻译单元中查找变量定义
        definitions = []
        
        def find_variable_definitions(cursor, var_name):
            # 检查是否为变量声明
            if cursor.kind == CursorKind.VAR_DECL and cursor.spelling == var_name:
                # 检查是否是定义（非extern声明）
                # 遍历子节点查找ExternStorageClass属性
                is_extern = False
                for token in cursor.get_tokens():
                    if token.spelling == 'extern':
                        is_extern = True
                        break
                
                # 如果不是extern声明，则认为是定义
                if not is_extern:
                    # 检查是否有初始化（定义通常包含初始化或赋值）
                    children = list(cursor.get_children())
                    # 变量定义通常会有初始化子节点
                    has_init = any(child.kind in [CursorKind.INTEGER_LITERAL, 
                                                CursorKind.STRING_LITERAL,
                                                CursorKind.CHARACTER_LITERAL,
                                                CursorKind.FLOATING_LITERAL,
                                                CursorKind.UNEXPOSED_EXPR,
                                                CursorKind.CALL_EXPR,
                                                CursorKind.INIT_LIST_EXPR] for child in children)
                    
                    # 如果有初始化或者有子节点，认为是定义
                    if has_init or children:
                        location = cursor.location
                        if location.file:
                            # 返回格式: 'filename:line_number'
                            # 使用实际的文件名而不是原始的file_path
                            file_name = location.file.name
                            # 移除PUT_ROOT_PATH前缀以保持一致性
                            if file_name.startswith(os.path.abspath(PUT_ROOT_PATH)):
                                file_name = os.path.relpath(file_name, PUT_ROOT_PATH)
                            definitions.append(f"{file_name}:{location.line}")
            
            # 递归遍历子节点
            for child in cursor.get_children():
                find_variable_definitions(child, var_name)
        
        find_variable_definitions(translation_unit.cursor, var_name)
        
        # 如果在当前翻译单元中找不到，尝试在整个项目中查找
        if not definitions:
            # 遍历整个PUT目录寻找.c文件
            put_path = os.path.abspath(PUT_ROOT_PATH)
            for root, dirs, files in os.walk(put_path):
                # 排除一些不必要的目录
                dirs[:] = [d for d in dirs if d not in ['.git', '.github', 't', 'scripts', 'doc', 'devtools', 'm4', 'vendor']]
                
                for file in files:
                    if file.endswith('.c'):
                        full_path = os.path.join(root, file)
                        # 避免重复解析原始文件
                        if full_path == os.path.abspath(full_file_path):
                            continue
                        
                        try:
                            tu = index.parse(full_path, args=['-I' + PUT_ROOT_PATH, '-std=c99'])
                            find_variable_definitions(tu.cursor, var_name)
                        except Exception as e:
                            # 如果解析某个文件失败，继续尝试其他文件
                            logging.warning(f"解析文件 {full_path} 时出错: {e}")
                            continue
        
        return definitions
    except Exception as e:
        logging.error(f"Error in find_var_definitions: {e}")
        import traceback
        logging.error(traceback.format_exc())
        return []