# SecClaw Functional Specification

## 1. Product overview

SecClaw is a local-first security operations agent that runs on the Dell Pro Max GB10. It provides a closed loop of discovery, analysis, approval, remediation, verification, and auditing for explicitly authorized enterprise networks and hosts.

The system uses a local large language model to process scan results, explain risks, and generate remediation plans. Network topology, service information, vulnerability findings, and conversation content remain on the local machine by default.

## 2. Product goals

- Continuously discover exposed services and common configuration risks in authorized assets.
- Convert raw scan results into understandable, sortable, and actionable risk reports.
- Generate remediation, verification, and rollback plans for each risk.
- Require human approval for every operation that changes system state.
- Rescan automatically after remediation and provide evidence that the risk was removed.
- Retain complete and unambiguous operational audit records.
- Complete core reasoning and demonstration workflows without an internet connection.

## 3. Non-goals

SecClaw does not provide the following capabilities:

- Scanning unauthorized public networks, event Wi-Fi, or third-party assets.
- Vulnerability exploitation, password brute forcing, phishing, persistence, or detection evasion.
- Automatic execution of unapproved high-risk remediation.
- Replacement for enterprise vulnerability management, SIEM, EDR, or patch-management platforms.
- Coverage of every operating system, cloud platform, and network device in the MVP.

## 4. Target users

- Small and medium-sized business IT administrators
- Security operations and SecOps teams
- DevOps, platform engineering, and SRE teams
- Organizations that need to process sensitive infrastructure data locally

## 5. Core use cases

### 5.1 Authorized scope configuration

Administrators must define the authorized scope before creating a scan job:

- Permitted IPv4 addresses or CIDR ranges
- Permitted hostnames
- Permitted port ranges
- Scan time windows
- Job owner and business justification
- Whether remediation is permitted

The system rejects out-of-scope targets, excessively broad public ranges, and scan requests without a job owner.

### 5.2 Security scanning

The system performs non-destructive scans of authorized assets and collects:

- Host reachability
- Open TCP ports
- Service names and limited version information
- TLS certificate status
- Common insecure services and exposure points
- Predefined configuration issues in the demonstration environment

The scanner must use fixed parameter templates. The LLM must never construct or directly execute arbitrary scan commands.

### 5.3 Risk analysis

The local LLM normalizes scan results into findings. Each finding contains:

- Title and unique identifier
- Affected asset
- Evidence
- Severity
- Business impact
- Confidence
- Recommended remediation
- Verification steps
- Rollback steps

Severity levels are `critical`, `high`, `medium`, `low`, and `info`.

### 5.4 Human approval

SecClaw sends summaries through Slack, Discord, or Telegram and offers these actions:

- View evidence
- View the proposed change
- Approve once
- Reject
- Defer
- Mark as accepted risk

Approval records must contain the approver, time, finding, command summary, and plan hash. Scan approval must not be treated automatically as remediation approval.

### 5.5 Sandbox remediation

OpenShell performs remediation in a restricted environment. Before execution, the following conditions must be satisfied:

- The target remains within the authorized scope.
- Approval has not expired.
- The actual plan matches the approved plan hash.
- A rollback plan has been generated.
- Commands come from an allowlist or controlled adapter.

The MVP supports these remediation types:

- Stop unnecessary services in demonstration containers.
- Adjust firewall rules in the demonstration environment.
- Change security configuration in demonstration applications.
- Update package or image configuration in demonstration containers.

### 5.6 Remediation verification

After remediation, the system automatically performs a scoped rescan and compares evidence from before and after the change. Finding states include:

- `open`
- `awaiting_approval`
- `remediating`
- `resolved`
- `failed`
- `accepted_risk`

A finding can become `resolved` only after rescan evidence proves that the issue is gone.

## 6. Functional requirements

### FR-01 Authorization policy

- The system must maintain an explicit target allowlist.
- Every scan job must reference a valid authorization policy.
- The system must revalidate the target separately before scanning and remediation.
- Denial events must be written to the audit log.

### FR-02 Scan jobs

- Users can create, start, cancel, and inspect scan jobs.
- Duplicate jobs for the same asset can be merged or queued.
- Scanning must support timeout, rate, and concurrency limits.
- Raw output and normalized results must be stored separately.

### FR-03 Finding management

- The system must deduplicate repeated findings consistently.
- Users can filter by asset, severity, status, and time.
- Every finding must link to its raw evidence.
- LLM inferences must be clearly distinguished from tool-observed facts.

### FR-04 Remediation plans

- Every plan must include prechecks, changes, verification, and rollback steps.
- A human-readable diff or equivalent change summary must be provided before execution.
- A plan changed after approval must be approved again.

### FR-05 Notifications and interaction

- The MVP must support at least one of Slack, Discord, or Telegram.
- Users can query risk summaries using natural language.
- Natural-language requests that change system state must be converted into structured plans and approved.

### FR-06 Auditing

- Record job creation, policy validation, tool calls, model conclusions, approvals, execution, and verification events.
- Every record contains a time, actor, action, object, result, and correlation ID.
- Sensitive credentials must not be written to logs.

### FR-07 Local operation

- Inference must run locally on the GB10.
- The core demonstration must work without a remote LLM API.
- The system must fail safely and must not perform remediation when the model service is unavailable.

## 7. System architecture

### 7.1 Components

- **OpenClaw**: agent orchestration, job state, and channel interaction.
- **NemoClaw**: local model inference, security analysis, and plan generation.
- **OpenShell**: restricted tool execution and remediation sandbox.
- **Scanner Adapter**: invokes local tools such as Nmap using fixed templates.
- **Policy Engine**: validates target scope, action type, and approval state.
- **Evidence Store**: stores raw scan results and rescan evidence.
- **Audit Store**: stores structured audit events.
- **Local Model Server**: provides model inference through a local API.

### 7.2 Data flow

1. The user submits an authorized scope and scan request.
2. The Policy Engine validates the target.
3. OpenShell executes a fixed scan template.
4. The Scanner Adapter normalizes tool output.
5. NemoClaw generates a risk explanation and candidate remediation plan.
6. OpenClaw sends the summary to a chat channel.
7. The user approves a specific plan.
8. The Policy Engine revalidates the plan and approval.
9. OpenShell performs the remediation.
10. The system rescans and updates the finding state.
11. The complete workflow is written to the Audit Store.

## 8. Security controls

- Deny every unauthorized target by default.
- Never insert user input directly into shell commands.
- Use structured schemas and allowlists for tool parameters.
- Cap scan rate, concurrency, and timeout.
- Perform remediation with a least-privilege identity.
- Provide credentials through environment injection or secret storage, never through prompts or logs.
- Make every state change traceable.
- Provide rollback and emergency-stop capabilities for high-risk remediation.
- Use isolated containers or a dedicated range network for demonstrations.

## 9. MVP scope

The one-day hackathon version must include:

- An isolated, intentionally vulnerable demonstration environment
- A CIDR/IP allowlist
- Non-destructive port and service scanning
- Local LLM risk summaries
- At least one remediable configuration issue
- Human approval through a chat channel
- OpenShell sandbox remediation
- Automatic rescanning and before-and-after comparison
- A simple web page or chat-style status display
- A complete audit timeline

## 10. Demonstration script

1. Show an authorization policy that permits only the demonstration network.
2. The user requests "Check the production simulation environment" through a chat channel.
3. SecClaw discovers an administrative port that should not be public.
4. The local model explains the risk and generates a firewall remediation plan.
5. The user reviews the diff and approves it.
6. OpenShell performs the change in the demonstration environment.
7. SecClaw rescans automatically and proves that the port is no longer exposed.
8. Show the audit timeline and local operation status.
9. Request a scan of an unauthorized target and show that the system explicitly rejects it.

## 11. Acceptance criteria

- The complete demonstration still works after disconnecting remote LLM services.
- Scan requests for unauthorized targets are rejected and audited.
- Scan results produce at least one evidence-backed finding.
- Remediation cannot run without approval.
- Approved remediation can affect only authorized demonstration targets.
- Rescanning can prove whether a finding has been resolved or remains present.
- The audit log can reconstruct the complete sequence of operations.
- The demonstration never exploits vulnerabilities or attacks third-party assets.

## 12. Non-functional requirements

- The initial screen or chat acknowledgement responds within three seconds.
- A small demonstration subnet scan completes within two minutes.
- Scanner failures do not cause the agent to perform unplanned remediation.
- Every core component can run on the GB10 as a container or local process.
- Job and finding state can be recovered after a service restart.

## 13. Future extensions

- Offline CVE and CISA KEV datasets
- Host baselines and CIS configuration checks
- Container image and software bill of materials analysis
- Multi-tenant authorization policies
- ServiceNow, Jira, and SIEM integrations
- Risk trends and SLA dashboards
- Signed remediation packages and two-person approval
