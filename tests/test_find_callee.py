#!/usr/bin/env python3
"""
测试 analysis_operators.find_callee 模块
"""

import os
import sys
import unittest

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis_operators.find_callee import find_callee

class TestFindCallee(unittest.TestCase):
    
    def test_find_callee_definition_in_source_file(self):
        """
        测试查找在源文件中定义的函数
        """
        # stats_prefix_clear函数在stats_prefix.c中定义
        source_location = "memcached/stats_prefix.c:20"
        function_name = "stats_prefix_clear"
        
        function_name_result, location_result = find_callee(source_location, function_name)
        print(f"\n查找在.c文件中定义的函数 '{function_name}' 在 '{source_location}' 的定义位置:")
        print(f"结果: function_name={function_name_result}, location={location_result}")
        # 我们期望能找到这个函数的定义
        self.assertIsNotNone(location_result)
        self.assertEqual(function_name_result, function_name)
        
    def test_find_callee_definition_in_header_file(self):
        """
        测试查找在头文件中声明的函数
        """
        # stats_prefix_init函数在stats_prefix.h中声明，在stats_prefix.c中使用
        source_location = "memcached/stats_prefix.c:18"
        function_name = "stats_prefix_init"
        
        function_name_result, location_result = find_callee(source_location, function_name)
        print(f"\n查找函数 '{function_name}' 在 '{source_location}' 的定义位置:")
        print(f"结果: function_name={function_name_result}, location={location_result}")
        # 我们期望能找到这个函数的定义
        self.assertIsNotNone(location_result)
        self.assertEqual(function_name_result, function_name)
        
    def test_find_callee_cross_file_definition(self):
        """
        测试查找在其他文件中定义的函数
        """
        # assoc_insert函数在assoc.c中定义，在items.c中使用
        source_location = "memcached/items.c:497"
        function_name = "assoc_insert"
        
        function_name_result, location_result = find_callee(source_location, function_name)
        print(f"\n查找在.c文件中定义并在其他.c文件中使用的函数 '{function_name}' 在 '{source_location}' 的定义位置:")
        print(f"结果: function_name={function_name_result}, location={location_result}")
        # 我们期望能找到这个函数的定义
        self.assertIsNotNone(location_result)
        self.assertEqual(function_name_result, function_name)
        
    def test_find_callee_nonexistent_function(self):
        """
        测试查找不存在的函数
        """
        source_location = "memcached/stats_prefix.c:18"
        function_name = "non_existent_function"
        
        function_name_result, location_result = find_callee(source_location, function_name)
        print(f"\n查找不存在的函数 '{function_name}' 在 '{source_location}' 的定义位置:")
        print(f"结果: function_name={function_name_result}, location={location_result}")
        # 我们期望找不到这个函数
        self.assertIsNone(location_result)
        self.assertIsNone(function_name_result)
        
    def test_find_callee_with_empty_function_name(self):
        """
        测试查找空函数名
        """
        source_location = "memcached/stats_prefix.c:18"
        function_name = ""
        
        function_name_result, location_result = find_callee(source_location, function_name)
        print(f"\n查找空函数名 '' 在 '{source_location}' 的定义位置:")
        print(f"结果: function_name={function_name_result}, location={location_result}")
        # 我们期望找不到这个函数
        self.assertIsNone(location_result)
        self.assertIsNone(function_name_result)

if __name__ == "__main__":
    unittest.main()