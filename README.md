# FPhandler

`FPhandler` 读取 SVFmemplus 的 Saber 告警及 `saber-report/v2` 报告，结合源码、报告语义和 `graph-reader` 查询能力，使用 LLM 将告警分类为 `TP`、`FP` 或 `UNCERTAIN`，并把结果写回原报告。

## 输入输出约定

`OUTPUT_DIR` 是统一管线管理文件的唯一目录：

- SVFmemplus 在其中写入 Saber TXT、Markdown、JSON 和 slice 文件；
- FPhandler 从其中发现 `svf_*.txt`，并读取同主名的 `*_report.json`；
- FPhandler 的日志、去重索引和语义规则库默认写入 `OUTPUT_DIR/fphandler/`；
- LLM 分类和扩增语义原子写回原 `*_report.json`。

例如：

```text
output/
├── svf_falconfs_extended_leak.txt
├── svf_falconfs_extended_leak_report.json
├── svf_falconfs_extended_leak_report.md
├── svf_falconfs_extended_leak_slices.json
└── fphandler/
    ├── RUN/
    ├── TRACE/
    ├── RESULT/
    ├── analyzed_locations.txt
    └── semantic_rules.json
```

## 环境与配置

安装 Python 依赖：

```bash
python -m pip install -r requirements.txt
```

复制配置模板：

```bash
cp config.example.py config.py
```

最小配置：

```python
PROJECT_ROOT = "/path/to/project/source"
OUTPUT_DIR = "/path/to/saber/output"

LINKED_BC_DIR = "/path/to/linked_bc_dir"
BITCODE_PATH = ""  # 为空时按 SAR 主名在 LINKED_BC_DIR 中解析 .bc

SAR_PATH = ""
SAR_PATHS = []
SAR_BATCH_DIRS = []

LLM_TYPE = "DeepSeek"  # DeepSeek / Qwen / Example / HW
GRAPH_READER_DOCKER_IMAGE = "nf-image:llvm21"
```

告警来源优先级：

1. `OUTPUT_DIR` 存在 `svf_*.txt` 时，直接使用该目录；
2. 否则使用非空的 `SAR_PATHS` 显式文件列表；
3. 否则扫描 `SAR_BATCH_DIRS`；
4. 最后回退到单个 `SAR_PATH`。

`SLICE_DIR` 通常保持为 `OUTPUT_DIR`。`RES_ROOT_PATH` 默认应设为：

```python
RES_ROOT_PATH = os.path.join(OUTPUT_DIR, "fphandler")
```

模型密钥通过环境变量提供：

```bash
export DEEPSEEK_API_KEY=sk-xxxxx
# 或
export QWEN_API_KEY=sk-xxxxx
```

## 执行

通用入口：

```bash
python run.py
```

只解析和统计告警，不启动 `graph-reader` 或调用 LLM：

```bash
python run.py --stats-only
```

也可使用 `script/object1/`、`script/object2/` 和 `script/object3/` 下的项目专用入口。

## 报告复用与写回

FPhandler 根据 TXT 文件主名定位同目录 `*_report.json`，直接使用已有字段：

- 源码位置与源码片段
- 稳定告警 ID
- 调用及值流轨迹
- 路径条件
- 求解器状态和摘要
- slice/cluster 信息

LLM 完成分类后，告警记录写入：

```json
{
  "triage": {
    "analysis_time": "ISO-8601 UTC time",
    "analysis_result": {
      "classification": "TP | FP | UNCERTAIN",
      "reason": "classification evidence",
      "function_name": "related function"
    },
    "source": "FPhandler"
  },
  "llm_enrichment": {
    "analysis_time": "ISO-8601 UTC time",
    "analysis_result": {
      "classification": "TP | FP | UNCERTAIN",
      "reason": "classification evidence",
      "function_name": "related function"
    },
    "semantic_facts": [],
    "source_context": "...",
    "path_conditions": [],
    "trace": []
  },
  "semantic_candidates": []
}
```

其中 `analysis_time + analysis_result` 是分类结果的稳定接口。顶层兼容字段仍会保留，供已有消费者继续读取。

UAF 可按释放位置聚类，uninit 可按 slice 聚类，以减少重复 LLM 调用。一个聚类得到结论后，结果会写回所有匹配的具体告警记录；缺少聚类信息时自动回退为逐条分析。

## 语义规则反馈

LLM 只在源码或 IR 证据足够时生成可复用的 `semantic_candidates`。候选规则以 `proposed` 状态追加到：

```text
OUTPUT_DIR/fphandler/semantic_rules.json
```

人工审核并导出：

```bash
python semantic_rules.py "$OUTPUT_DIR/fphandler/semantic_rules.json" \
  --approve '<rule-id>' \
  --export-approved "$OUTPUT_DIR/fphandler/semantic_rules.approved.json"
```

再由 Saber 加载批准后的规则：

```bash
saber -uninit \
  -saber-semantic-rules="$OUTPUT_DIR/fphandler/semantic_rules.approved.json" \
  -report-dir="$OUTPUT_DIR" \
  input.bc
```

规则支持 `initializer`、`memory_transfer`、`allocator`、`deallocator`、`resource_open`、`resource_close`、`ownership_transfer`、`heap_object_summary` 和 `domain_hint`。当前直接参与求解的是初始化、内存传输和资源 API；其他类型作为可审计证据及后续分析扩展接口。

## 主要代码

- `run.py`：告警发现、任务调度和统计入口
- `saber_report.py`：v2 报告读取、上下文复用和原子写回
- `alter_handler.py`：TXT/SAR 告警解析
- `free_analyzer.py`：LLM 研判流程
- `command_caller.py`：`graph-reader` 生命周期与通信
- `semantic_rules.py`：语义规则审核和导出
- `config.example.py`：统一目录配置模板
