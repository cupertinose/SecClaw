# SecClaw

SecClaw 是一个本地优先、默认拒绝、人工审批后才允许修复的安全运维 MVP。当前实现仅使用 Python 标准库，数据保存在本机 SQLite 中；扫描器使用固定 TCP connect 模板，不会拼接或执行用户提供的 shell 命令。

## 已实现

- IPv4/CIDR、主机名、端口和时间窗口授权策略
- 有并发、速率和超时上限的非破坏性端口扫描
- 原始证据与标准化发现项分开持久化，发现项稳定去重
- 修复计划、可读变更摘要、计划哈希和限时人工审批
- 受控 `demo_firewall_v1` 修复适配器、自动复扫、回滚
- 结构化审计时间线（不记录请求头、环境变量或凭证）
- 本地 JSON API 和命令行入口
- 通过本机 Ollama 生成有事实引用的中文风险摘要；模型不可用时安全失败
- 可选 Discord webhook 计划通知（URL 只从环境变量读取，不写入审计）

`demo_firewall_v1` 是隔离演示用适配器：它在 SecClaw 的本地状态中模拟端口访问规则，不修改宿主机防火墙。生产适配器需另行接入 OpenShell，并保持相同的审批和哈希校验边界。

## 快速开始

```bash
python3 -m secclaw --data-dir .secclaw serve
```

创建仅允许本机演示端口的策略：

```bash
python3 -m secclaw create-policy \
  --owner admin --reason "隔离演示环境" \
  --target 127.0.0.1 --ports 8080,8443 --allow-remediation
```

命令会输出策略 ID。启动扫描：

```bash
python3 -m secclaw scan --policy <策略ID> --target 127.0.0.1 --ports 8080
```

完整的计划、审批和修复流程通过 API 提供：

```text
POST /api/findings/{finding_id}/plan
POST /api/summary                      {"severity":"high"}
POST /api/plans/{plan_id}/decision   {"decision":"approved"}
POST /api/plans/{plan_id}/execute
POST /api/plans/{plan_id}/rollback
GET  /api/audit
```

所有改变状态的请求可通过 `X-SecClaw-Actor` 标识操作人。服务默认只监听 `127.0.0.1:8787`，不包含身份认证；如需对外提供，应放在企业认证反向代理后。

如需发送 Discord 审批摘要，在启动服务前设置 `SECCLAW_DISCORD_WEBHOOK`。通知只包含发现项、变更摘要和计划哈希；审批动作仍由本地 API 完成，避免 webhook 成为越权执行入口。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 调用本地 Ollama

客户端只使用 Python 标准库，默认连接本机 Ollama，并调用
`local-gpt-oss-120b:latest`：

```bash
./scripts/ollama_chat.py "请总结当前扫描结果"
```

查看已安装模型：

```bash
./scripts/ollama_chat.py --list-models
```

指定其他模型或从标准输入读取问题：

```bash
echo "解释 22 端口暴露的风险" | ./scripts/ollama_chat.py --model qwen3:30b-a3b
```

也可以通过环境变量配置：

```bash
export OLLAMA_HOST=http://127.0.0.1:11434
export OLLAMA_MODEL=local-gpt-oss-120b:latest
```
