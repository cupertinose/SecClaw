# SecClaw

SecClaw is a local-first, default-deny security operations MVP that permits remediation only after human approval. The current implementation uses only the Python standard library and stores data in a local SQLite database. The scanner uses a fixed TCP connect template and never constructs or executes shell commands supplied by users.

## Implemented features

- Authorization policies for IPv4/CIDR ranges, hostnames, ports, and time windows
- Non-destructive port scanning with concurrency, rate, and timeout limits
- Separate persistence of raw evidence and normalized findings, with stable finding deduplication
- Remediation plans, human-readable change summaries, plan hashes, and time-limited human approvals
- Controlled `demo_firewall_v1` remediation adapter, automatic rescanning, and rollback
- Structured audit timeline that does not record request headers, environment variables, or credentials
- Local JSON API and command-line interface
- Evidence-grounded English risk summaries generated with local Ollama; safe failure when the model is unavailable
- Optional Discord webhook plan notifications; the URL is read only from the environment and is never written to the audit log

`demo_firewall_v1` is an isolated demonstration adapter. It simulates port access rules in SecClaw's local state without changing the host firewall. A production adapter must integrate with OpenShell separately while preserving the same approval and hash-validation boundaries.

## Quick start

```bash
python3 -m secclaw --data-dir .secclaw serve
```

Create a policy that permits only local demonstration ports:

```bash
python3 -m secclaw create-policy \
  --owner admin --reason "isolated demonstration environment" \
  --target 127.0.0.1 --ports 8080,8443 --allow-remediation
```

The command prints the policy ID. Start a scan:

```bash
python3 -m secclaw scan --policy <policy-id> --target 127.0.0.1 --ports 8080
```

The complete planning, approval, and remediation workflow is available through the API:

```text
POST /api/findings/{finding_id}/plan
POST /api/summary                      {"severity":"high"}
POST /api/plans/{plan_id}/decision   {"decision":"approved"}
POST /api/plans/{plan_id}/execute
POST /api/plans/{plan_id}/rollback
GET  /api/audit
```

State-changing requests can identify the operator with `X-SecClaw-Actor`. By default, the service listens only on `127.0.0.1:8787` and does not include authentication. Place it behind an enterprise-authenticated reverse proxy before exposing it externally.

To send Discord approval summaries, set `SECCLAW_DISCORD_WEBHOOK` before starting the service. Notifications contain only the finding, change summary, and plan hash. Approval still occurs through the local API so that the webhook cannot become an unauthorized execution path.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Using local Ollama

The client uses only the Python standard library. By default, it connects to local Ollama and invokes `local-gpt-oss-120b:latest`:

```bash
./scripts/ollama_chat.py "Summarize the current scan results"
```

List installed models:

```bash
./scripts/ollama_chat.py --list-models
```

Select another model or read the prompt from standard input:

```bash
echo "Explain the risk of exposing port 22" | ./scripts/ollama_chat.py --model qwen3:30b-a3b
```

You can also configure the client with environment variables:

```bash
export OLLAMA_HOST=http://127.0.0.1:11434
export OLLAMA_MODEL=local-gpt-oss-120b:latest
```
