# FPhandler

## 模块功能

`FPhandler` 是交付件3“基于大模型推理的定向选择性缺陷告警检测方法”的源码实现。  
该模块读取 `SVFmemplus` 产出的告警报告（SAR），结合 `graph-reader` 提供的中间表示语义查询能力，完成告警自动研判（TP/FP/UNCERTAIN）。

## 环境配置

请先按交付目录中的环境脚本准备运行环境，并安装 `requirements.txt` 依赖。

## 目录说明

```text
FPhandler/
├── config.py           # 运行配置
├── run.py              # 主入口
├── command_caller.py   # graph-reader 拉起与通信
├── alter_handler.py    # SAR 告警解析
├── free_analyzer.py    # LLM 研判流程
├── tools.py            # 分析工具接口
├── RES/                # 输出目录（运行后自动生成）
└── SAR/                # 建议放置 SVFmemplus 告警文件
```

## 关键配置（`config.py`）

最小必配项：

```python
PROJECT_ROOT = "/path/to/project/source"
LINKED_BC_DIR = "/path/to/linked_bc_dir"
BITCODE_PATH = ""          # 为空时，按 SAR 文件主名在 LINKED_BC_DIR 下解析同名 .bc
SAR_PATH = "/path/to/xxx.txt"
SAR_BATCH_DIRS = []        # 批量分析目录列表，非空时优先于 SAR_PATH
LLM_TYPE = "DeepSeek"      # 可选：DeepSeek / Qwen / Gemini
```

说明：

- 单文件模式：使用 `SAR_PATH`
- 批处理模式：使用 `SAR_BATCH_DIRS`（会遍历目录下全部 `.txt`）
- 去重文件：`ANALYZED_LOCATIONS_FILE`（默认在 `RES` 下），用于跳过已完成结论的告警

## 模型密钥

```bash
export DEEPSEEK_API_KEY=sk-xxxxx
# 或
export QWEN_API_KEY=sk-xxxxx
```

## 执行

```bash
python run.py
```

执行流程：

- 读取 SAR 告警并解析为结构化缺陷对象
- 按“缺陷类型 + 源码位置”去重
- 按 SAR 解析对应 `.bc`，启动/复用 `graph-reader`
- 调用 LLM + 工具链进行逐条研判
- 写入结果与日志

## 输出产物

- `RES/RUN/`：任务运行日志
- `RES/TRACE/`：模型与工具调用过程日志
- `RES/RESULT/`：最终研判结论日志
- `RES/analyzed_allocation_locations.txt`：已完成结论告警的位置去重索引

## 与交付件2联动

`FPhandler` 依赖 `SVFmemplus` 的两个输出：

- 告警文本（SAR）作为输入待研判集合
- `graph-reader` 作为语义查询后端（函数、路径、值流、节点信息等）

建议先完成 `SVFmemplus` 构建并确保 `graph-reader` 可执行，再运行本模块。
