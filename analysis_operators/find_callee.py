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

def find_callee(source_location, function_name):
    """
    找到被调用函数的函数体
    return: function_name, source_location
    """
    # 基于LLVM来实现不要使用基于文本的查找
    # libclang
    if not libclang_available:
        return None, None
    
    try:
        # 解析source_location获取文件路径
        file_path = source_location.split(":")[0]
        
        # 构造完整的文件路径
        full_file_path = os.path.join(PUT_ROOT_PATH, file_path)
        
        # 使用libclang解析文件，它会自动处理包含的头文件
        index = cindex.Index.create()
        # 传递适当的解析选项，确保包含的文件也被解析
        translation_unit = index.parse(full_file_path, args=['-I' + PUT_ROOT_PATH])
        
        if not translation_unit:
            return None, None
            
        # 在整个翻译单元中查找函数定义
        def find_function_def(cursor, function_name):
            # 如果当前节点是函数声明且名称匹配
            if cursor.kind == CursorKind.FUNCTION_DECL and cursor.spelling == function_name:
                # 检查是否有函数体（子节点），如果有则为定义
                children = list(cursor.get_children())
                # 函数定义通常会有子节点（参数、复合语句等）
                if children:
                    # 检查是否包含复合语句（函数体）
                    has_compound_stmt = any(child.kind == CursorKind.COMPOUND_STMT for child in children)
                    if has_compound_stmt:
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
                result = find_function_def(child, function_name)
                if result:
                    return result
            return None
        
        result = find_function_def(translation_unit.cursor, function_name)
        
        # 如果在当前翻译单元中找不到，尝试在整个项目中查找
        if not result:
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
                            tu = index.parse(full_path, args=['-I' + PUT_ROOT_PATH])
                            result = find_function_def(tu.cursor, function_name)
                            if result:
                                break
                        except:
                            # 如果解析某个文件失败，继续尝试其他文件
                            continue
        
        if result:
            return function_name, result
        else:
            return None, None
    except Exception as e:
        logging.error(f"Error in find_callee: {e}")
        return None, None