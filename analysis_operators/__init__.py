# 分析操作符包

import importlib

# 变量相关操作
# from .find_var_decl import find_var_decl
find_var_decl_module = importlib.import_module('analysis_operators.find_var_decl')
find_var_decl = find_var_decl_module.find_var_decl
# from .find_var_definitions import find_var_definitions
find_var_definitions_module = importlib.import_module('analysis_operators.find_var_definitions')
find_var_definitions = find_var_definitions_module.find_var_definitions

# 函数相关操作
# from .find_callers import find_callers
find_callers_module = importlib.import_module('analysis_operators.find_callers')
find_callers = find_callers_module.find_callers
# from .find_callee import find_callee
find_callee_module = importlib.import_module('analysis_operators.find_callee')
find_callee = find_callee_module.find_callee
# from .find_function_definition import find_function_definition
# find_function_definition_module = importlib.import_module('analysis_operators.find_function_definition')
# find_function_definition = find_function_definition_module.find_function_definition

# 符号相关操作
# from .ctags_readtags import ctags_readtags
ctags_readtags_module = importlib.import_module('analysis_operators.ctags_readtags')
ctags_readtags = ctags_readtags_module.ctags_readtags

# 路径约束相关操作
# from .get_path_constraint import get_path_constraint
find_path_constraint_module = importlib.import_module('analysis_operators.get_path_constraint')
get_path_constraint = find_path_constraint_module.get_path_constraint

# from .check_always_implying import check_always_implying
check_always_implying_module = importlib.import_module('analysis_operators.check_always_implying')
check_always_implying = check_always_implying_module.check_always_implying

# from .check_le import check_le
check_le_module = importlib.import_module('analysis_operators.check_le')
check_le = check_le_module.check_le

# 上下文相关操作
# from .dump_source_file import dump_source_file
dump_source_file_module = importlib.import_module('analysis_operators.dump_source_file')
dump_source_file = dump_source_file_module.dump_source_file

# from .dump_func_context import dump_func_context
dump_func_context_module = importlib.import_module('analysis_operators.dump_func_context')
dump_func_context = dump_func_context_module.dump_func_context

__all__ = [
    'find_var_decl',
    'find_var_definitions',
    'find_callers',
    'find_callee',
    # 'find_function_definition',
    'ctags_readtags',
    'get_path_constraint',
    'check_always_implying',
    'check_le',
    'dump_source_file',
    'dump_func_context'
]