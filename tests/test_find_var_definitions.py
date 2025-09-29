#!/usr/bin/env python3
"""
测试 analysis_operators.find_var_definitions 模块
"""

import os
import sys
import unittest

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis_operators.find_var_definitions import find_var_definitions

class TestFindVarDefinitions(unittest.TestCase):
    
    def test_find_var_definitions_in_source_file(self):
        """
        测试查找在.c文件中定义的变量
        """
        # 选择memcached/stats_prefix.c中的一个变量进行测试
        source_location = "memcached/stats_prefix.c:18"
        var_name = "num_prefixes"
        result = find_var_definitions(source_location, var_name)
        print(f"\n查找在.c文件中定义的变量 '{var_name}' 在 '{source_location}' 的定义位置:")
        print(f"结果: {result}")
        self.assertIsInstance(result, list)
        
    def test_find_var_definitions_cross_file(self):
        """
        测试跨文件查找变量定义
        """
        # 选择一个在头文件中声明但在源文件中定义的变量
        source_location = "memcached/memcached.c:18"
        var_name = "total_prefix_size"  # 这是在memcached.c中定义的全局变量
        result = find_var_definitions(source_location, var_name)
        print(f"\n查找在其他文件中定义的变量 '{var_name}' 在 '{source_location}' 的定义位置:")
        print(f"结果: {result}")
        self.assertIsInstance(result, list)
        
    def test_find_var_definitions_nonexistent_variable(self):
        """
        测试查找不存在的变量
        """
        source_location = "memcached/stats_prefix.c:18"
        var_name = "non_existent_variable_xyz"
        result = find_var_definitions(source_location, var_name)
        print(f"\n查找不存在的变量 '{var_name}' 在 '{source_location}' 的定义位置:")
        print(f"结果: {result}")
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)  # 应该返回空列表
        
    def test_find_var_definitions_with_empty_var_name(self):
        """
        测试查找空变量名
        """
        source_location = "memcached/stats_prefix.c:18"
        var_name = ""
        result = find_var_definitions(source_location, var_name)
        print(f"\n查找空变量名 '' 在 '{source_location}' 的定义位置:")
        print(f"结果: {result}")
        self.assertIsInstance(result, list)

if __name__ == "__main__":
    unittest.main()