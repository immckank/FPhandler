# 分层分析工作流 (Layered Analysis Workflow)

本目录包含一个实验性的、用于静态分析告警（SAST Alert）分类的分层工作流。

其核心目标是通过引入一个轻量级的预分析阶段来提升整体的分析效率和准确性。

## 工作原理

本工作流采用两阶段（Two-Tier）分析策略，由 `run_layered.py` 脚本进行编排。

### 第一层：函数功能分析 (Tier 1: Function Analysis)

- **执行脚本**: `func_analyzer_layered.py`
- **目标**: 快速过滤掉明显的误报 (False Positives)。
- **逻辑**:
    1.  首先，使用基于函数控制流的轻量级分析器 (`FunctionAnalysisModel`) 对告警进行初步判断。
    2.  如果分析器能够在此阶段得出结论，特别是确认告警为 **误报 (FP)**，则整个分析流程终止，并返回结果。这避免了后续更耗时的分析，从而节省了时间和资源。
    3.  如果结论是 **真报 (TP)** 或 **不确定 (UNCERTAIN)**，则将告警传递给下一层进行深度分析。

### 第二层：路径分析 (Tier 2: Path Analysis)

- **执行脚本**: `path_analyzer_layered.py`
- **目标**: 对第一层无法确定的告警进行深入、精确的判断。
- **逻辑**:
    1.  接收到来自第一层的告警后，启动基于值流图（Value-Flow Graph）的路径敏感分析器。
    2.  此分析器会沿着程序执行路径追踪变量的内存状态，以得出最终的、更可靠的结论。
    3.  与函数分析器类似，该分析器也采用了模板方法模式，将核心分析循环、工具调用等逻辑封装在基类 `PathAnalyzerModel` 中，并通过 `DeepSeekPathAnalyzer` 等子类实现特定模型的适配。

## 代码修改说明

为了实现上述工作流并保持代码的整洁，我们进行了以下修改：

1.  **创建 `layered_workflow` 目录**:
    -   所有实验性代码都被隔离在此目录中，以避免对主工作流产生影响。

2.  **`run_layered.py`**:
    -   这是新工作流的入口点。
    -   它被修改为按顺序执行两阶段分析：首先调用 `Function Analyzer`，并根据其返回结果决定是否需要调用 `Path Analyzer`。

3.  **`func_analyzer_layered.py`**:
    -   这是对原 `func_analyzer.py` 的一次重要重构，应用了**模板方法设计模式**。
    -   **提取公共逻辑**: 创建了一个抽象基类 `FunctionAnalysisModel`，并将模型对话、工具调用、循环处理等通用逻辑提取到了核心的 `_analysis_loop` 方法中。
    -   **引入钩子方法**: 为了处理像 `Qwen` 模型这种会返回特殊XML格式结论的“非标准”行为，我们引入了 `_post_response_hook` 方法。子类 (如 `QwenFunctionAnalyzer`) 可以重写此方法来添加自己独特的逻辑，而无需修改主循环。这极大地提升了代码的可扩展性并消除了冗余。

4.  **`path_analyzer_layered.py`**:
    -   这是为分层工作流定制的路径分析器，同样应用了模板方法设计模式。
    -   **抽象基类 `PathAnalyzerModel`**: 封装了路径分析的核心逻辑，包括与 SVF 后端交互、分析路径的迭代、以及工具调用等。
    -   **模型适配**: 提供了 `DeepSeekPathAnalyzer` 等子类，用于适配不同大语言模型的特定输出格式和行为。例如，`DeepSeekAdapter` 方法专门用于修正 DeepSeek 模型返回的行号不精确的问题。
    -   **状态**: 经过近期对 `TypeError` 和 `AttributeError` 的修复，该路径分析器已能稳定处理复杂的内存状态追踪，并成功运行。

5.  **`llm_layered.py`**:
    -   此文件包含了用于两阶段分析的具体分析器实现，例如 `DeepSeekFunctionAnalyzer` 和 `QwenFunctionAnalyzer`。
    -   它的 `import` 语句已被更新，以确保它调用的是当前目录下的 `func_analyzer_layered.py` 和 `path_analyzer_layered.py`。

## 如何运行实验

要启动这个新的分层工作流，请在项目的根目录下运行以下命令：

```bash
# 开启虚拟环境
source FP/bin/activate
# 运行分层工作流
python layered_workflow/run_layered.py
```
## 工作结果
1.第一层工作流利用Function可以快速做出判断，针对报TP的警报，使用PATH进一步分析。对于libtiff项目，可以实现误报完全消除，还需换数据集验证误报消除能力，以及正报发现能力。