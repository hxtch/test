# Baseline Update

本 skill 默认直接使用：

- `references/permissions.txt`
- `references/protected-broadcasts.txt`

`protected-broadcasts.txt` 固定为一行一个 action，扫描器和 LLM 深挖共用同一份文件，不生成 XML 派生文件。

## 更新权限定义

```bash
SKILL_DIR=/path/to/android-dynamic-broadcast-llm-review-orchestrator
adb shell pm list permissions -f > "$SKILL_DIR/references/permissions.txt"
```

要求：

- 保持 `pm list permissions -f` 原始风格
- 不要手工改成“一行一个 permission”

## 更新保护广播

```bash
SKILL_DIR=/path/to/android-dynamic-broadcast-llm-review-orchestrator
adb shell dumpsys package | grep 'Protected broadcast ' -A 2000 | \
sed -n 's/.*Protected broadcast[[:space:]]*//p' | \
sed 's/\r$//' | sed '/^$/d' > "$SKILL_DIR/references/protected-broadcasts.txt"
```

要求：

- 最终文件保持一行一个 action
- 不能混入 `exported`、XML 标签、空字符串或其他非 action 文本
- 如果某些 action 使用前缀通配，保留 `xxx.*` 语义
