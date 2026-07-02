# FPhandler

FPhandler 直接读取 SVFmemplus 生成的单警报 JSON，结合源码和
`graph-reader` 查询，将 Agent 结论原子写回同一文件的
`classification` 与 `reason` 字段。

## 输入

统一管线按 `defect_types` 从 `OUTPUT_DIR/alerts` 读取对应类别：

```text
alerts/
├── memory_leak/<sha256>.json
├── double_free/<sha256>.json
├── use_after_free/<sha256>.json
├── uninit_use/<sha256>.json
└── buffer_overflow/<sha256>.json
```

除内存泄漏外，每条警报包含一条裁剪后的 SVFG 值流 `path`。内存泄漏的
`paths` 表示可能安全释放对象的路径，`leak_condition` 表示这些安全条件
并集的补集。

FPhandler 信任 checker 生成的结构，不做告警 schema 校验，不读取终端文本，
不做跨文件 slice 对齐，也不按源码位置猜测警报对应关系。

## 执行

```bash
./script/run_pipeline.sh
./script/run_pipeline.sh --fph-only --stats-only
```

也可直接运行：

```bash
source script/lib/common.sh && load_config
cd FPhandler
python3 run.py --config ../script/config.py
```

已有 `classification` 的警报会被跳过。`--stats-only` 只统计 JSON，
不会启动 graph-reader 或调用模型。

UAF 按 free 位置、UNINIT 按对象类型、BOF 按访问类型组成最多
`ALERT_BATCH_SIZE`（默认 8）条的请求。Agent 只看到 `B0001-A01` 形式的
批内短 ID；磁盘中的 SHA-256
canonical ID 不变。一次 conclusion 可用 `alert_ids` 覆盖一条或多条警报，
也可分多轮提交不同结论。循环仅在本批全部 ID 已分类后结束并统一写回。
统一只暴露 `set_conclusion`：每次调用必须传入 1–N 个 `alert_ids`，同一次
调用中的 ID 共享分类和理由；不同结论可分多次调用。如果模型只返回文本分析，
下一轮会强制调用该工具。RUN 日志会为
每个成功落盘的警报记录 `wrote conclusion`，TRACE 会记录每轮响应、工具调用
以及尚未完成的短 ID。

任一批次未完整分类或写回失败时，进程返回非零退出码。

Agent 默认最多运行 32 轮，并至少保留最后 10 轮（或批大小 + 2，取较大值）
强制提交结论。可通过 `AGENT_MAX_TURNS` 和
`AGENT_CONCLUSION_RESERVE_TURNS` 调整。

## 测试

```bash
python3 -m unittest discover -p 'test_*.py'
```
