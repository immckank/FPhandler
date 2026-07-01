# FPhandler

FPhandler 直接读取 SVFmemplus 生成的单警报 JSON，结合源码和
`graph-reader` 查询，将 Agent 结论原子写回同一文件的
`classification` 与 `reason` 字段。

## 输入

统一管线从 `OUTPUT_DIR/alerts` 递归发现警报：

```text
alerts/
├── memory_leak/<sha256>.json
├── double_free/<sha256>.json
├── use_after_free/<sha256>.json
└── uninit_use/<sha256>.json
```

除内存泄漏外，每条警报包含一条裁剪后的 SVFG 值流 `path`。内存泄漏的
`paths` 表示可能安全释放对象的路径，`leak_condition` 表示这些安全条件
并集的补集。

FPhandler 不读取 Saber 终端文本，不做跨文件 slice 对齐，也不按源码位置
猜测警报对应关系。

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

已有 `classification` 的警报会被跳过。`--stats-only` 只校验和统计 JSON，
不会启动 graph-reader 或调用模型。

UAF 按 free 位置、UNINIT 按对象类型组成最多 `ALERT_BATCH_SIZE` 条的请求。
批处理工具要求 Agent 为批次内每个 `alert_id` 返回独立
`classification/reason`；ID 集不完整时整批拒绝写回。

## 测试

```bash
python3 -m unittest test_alert_document.py
```
