# FPhandler

## 模块功能

本模块将提供针对静态分析报告(预期分析格式为SVFmem+产出的分析格式)，执行由智能体驱动的自动化分析流程。

## 环境配置

请参考dockerfile中给出的环境要求，在镜像构建完成后匹配对应的config并整理文件格式。

以下以分析libtiff项目的路径格式与配置信息为例

 1. FPhandler目录结构
    ```
    FPhandler
    ├── PUT # 待测试程序路径，存放源码和bitcode文件
    ├── RES # 模型分析结果的存放路径 留空
    ├── SAR # 静态分析结果报告的路径，存放缺陷报告
    └── 其他
    ```
    PUT目录示例
    ```
    PUT/
    ├──libtiff_{commit hash 1}/
    |   ├──libtiff/     #这一版本的libtiff项目源码
    |   └──libtiff.bc
    ├──libtiff_{commit hash 2}/
    |   ├──libtiff/     #这一版本的libtiff项目源码
    |   └──libtiff.bc
    └──...
    ```
2. 修改config.py配置
    需要修改这几个变量
    ```python
    PUT_ROOT_PATH = "PUT/libtiff_{commit hash}"
    PUT_NAME = "libtiff" # 编译出的bc文件的文件名，放在PUT_ROOT_PATH下
    PROJECT_NAME = "libtiff" # 项目文件夹名称，放在PUT_ROOT_PATH下
    sar_name = "libtiff_{commit hash}.txt" # 静态分析报告，需放在SAR_ROOT_PATH下
    ```
    
    其他配置选项说明
    ```python
    # LLM_TYPE = "DeepSeek" 支持Qwen / DeepSeek
    LLM_TYPE = "DeepSeek"
    # free / function / path 目前成熟的解决方案为free模式 不同分析模式workflow不同 复杂分析模式可能未实现
    ANALYZER_TYPE = "free"
    ```

3. 导出API_KEY环境变量

```bash
export DEEPSEEK_API_KEY=sk-xxxxx # 以deepseek为例
```
    
## 执行模型分析

```bash
python run.py
```

## 其他说明

实现其他模型的支持只需要实现clinet对应方法即可(openai库)，参考以下DeepSeek实现

```python
# analyzers/free_analyzer.py L183-211
class DeepSeekFreeAnalyzer(FreeAnalysisModel):
    def __init__(self, model_name="deepseek-chat"):
    # 以下是主要区别 初始化client / model_name即可
        super().__init__()
        self.model_name = model_name
        self.client = OpenAI(
            api_key=os.environ.get("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
        )
            
    def responseToAlter(self, alter_prompt, user_prompt=""):
    # 测试使用的方法 dummy function
        return None
    
    def responseForAlter(self, alter:memory_defect.MemoryLeak):
        super().responseForAlter(alter)

```

```python
# analyzers/analyzer_builder.py L10-16
# 工厂模式生成分析器 加入实例创建即可
    if ANALYZER_TYPE == "free":
        if LLM_TYPE == "Gemini":
            return GeminiFreeAnalyzer()
        elif LLM_TYPE == "DeepSeek":
            return DeepSeekFreeAnalyzer()
        elif LLM_TYPE == "Qwen":
            return QwenFreeAnalyzer()
        else:
            raise ValueError(f"Unknown LLM type: {LLM_TYPE}")
```
