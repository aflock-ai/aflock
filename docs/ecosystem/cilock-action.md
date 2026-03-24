---
sidebar_position: 2
---

# cilock

Protecting against malicious GitHub Actions and compromised packages.

An attacker hijacked a popular GitHub Action. Every pipeline using it started exfiltrating secrets — SSH keys, cloud credentials, Kubernetes tokens, all to an attacker-controlled domain. That's the real story of the [trivy-action compromise](https://testifysec.com/blog/cilock-action-supply-chain-attacks). Five days later, the [same playbook hit PyPI](https://testifysec.com/blog/cilock-litellm-supply-chain-attack) — `litellm==1.82.8` shipped a `.pth` credential stealer that runs on every Python interpreter startup.

The industry response was "pin your SHAs." That's one lock on a building that needs three.

## Three Layers That Kill These Attacks

### Prevention

Policy blocks unapproved action sources before they execute. Tag rewrite is irrelevant if you enforce source and SHA pinning.

```rego
package cilock.verify

import rego.v1

approved_sources := ["chainguard-dev/", "your-org/", "actions/"]

deny contains msg if {
    not source_approved(input.actionref)
    msg := sprintf("Action from untrusted source: %s", [input.actionref])
}

deny contains msg if {
    not input.refpinned
    msg := sprintf("Action not pinned to SHA: %s", [input.actionref])
}
```

### Content Detection

Recursive secret scanning catches credential harvesting in build output, even through layers of base64 encoding. The LiteLLM attacker used double base64. cilock decodes at each depth and runs Gitleaks pattern matching against the decoded content. `--attestor-secretscan-fail-on-detection` blocks the build.

### Behavioral Detection

Syscall tracing + OPA policy catches covert exfiltration that never hits stdout. The attacker writes creds to files, encrypts, and POSTs them out. cilock's `--trace` intercepts every file open and an OPA policy flags the filesystem access pattern:

```rego
deny contains msg if {
    some proc in input.processes
    some file in object.keys(proc.openedfiles)
    startswith(file, "/tmp/runner_collected")
    msg := sprintf("Credential harvesting: %s (PID %d) opened %s",
        [proc.program, proc.processid, file])
}
```

No legitimate `pip install` reads SSH keys, AWS credentials, and Kubernetes configs. Content scanning catches what the attacker prints. Behavioral detection catches what the attacker does. Prevention stops the attacker from running at all.

## Cryptographic Verification — Not Just Logging

Every cilock attestation is signed with Fulcio OIDC (short-lived certificates tied to GitHub Actions identity), timestamped by Sigstore TSA (RFC 3161), and verified against a signed Rego policy. If anything fails, the release is blocked.

Pinning is a lock. Attestation is a security camera, a receipt, and a notary.

## How cilock Relates to aflock

| Layer | Project | Role |
|-------|---------|------|
| **CI/CD Security** | **cilock** | Prevents supply chain attacks in CI/CD pipelines |
| **Agent Security** | [aflock](https://github.com/aflock-ai/aflock) | Constrains AI agent behavior with signed policies |
| **Attestation** | [Rookery](https://github.com/aflock-ai/rookery) | Cryptographic evidence generation — the shared foundation |

aflock constrains what AI agents can do. cilock constrains what CI/CD pipelines can do. Both generate [Rookery](./rookery.md) attestations, both verify against OPA policies, and both use Sigstore for signing.

## Proven Against Real Attacks

Tested in a [public repository](https://github.com/aflock-ai/cilock-trivy-detection-test) with live GitHub Actions workflows:

- **Attack reproduction** — reproduces the TeamPCP credential harvesting technique (stdout + base64 stealer). Secretscan catches it.
- **Covert variant** — reproduces the file-based exfiltration pattern (nothing to stdout). Trace + OPA catches it.
- **Real Trivy scan** — wraps actual `trivy image` against a Docker image. cilock works on production workloads, not just attack reproductions.

All verified end-to-end with Fulcio OIDC + Sigstore TSA.

## Quick Example

```yaml
- uses: aflock-ai/cilock-action@v0.0.1
  with:
    step: build
    command: "npm run build"

# Wrap a third-party action with secret scanning
- uses: aflock-ai/cilock-action@v0.0.1
  with:
    step: trivy-scan
    action-ref: "aquasecurity/trivy-action@7b7aa264d718dc28d43f6a611f86ab9880e3d87a"
    action-inputs: '{"image-ref": "myapp:latest"}'
    attestations: "environment git github secretscan"
    cilock-args: "--attestor-secretscan-fail-on-detection"
```

## What cilock Does Not Do

- **Detection is post-execution.** If secrets are exfiltrated during the run, the exfiltration has already happened. cilock blocks the release and provides forensic evidence.
- **No network egress monitoring.** The HTTPS POST to the attacker's C2 domain would not be detected.
- **Trace requires opt-in.** Without `--trace`, covert file-based attacks evade content scanning.

## Full Technical Breakdown

- [75 Poisoned Tags and Nobody Noticed](https://testifysec.com/blog/cilock-action-supply-chain-attacks) — Trivy attack analysis
- [A .pth File, 34KB of Base64, and Every Secret You Have](https://testifysec.com/blog/cilock-litellm-supply-chain-attack) — LiteLLM attack analysis

## Learn More

- [cilock on GitHub](https://github.com/aflock-ai/cilock-action)
- [Rookery](./rookery.md) — the attestation framework cilock is built on
- [TestifySec](./testifysec.md) — the company behind these projects
