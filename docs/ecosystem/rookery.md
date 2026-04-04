---
sidebar_position: 0
---

# Rookery

:::caution Active Development
Rookery is under active development and has not had a stable release yet. The documentation site is being built out — more detailed docs will be added soon. If you have questions or want to contribute, join the [discussions](https://github.com/orgs/aflock-ai/discussions).
:::

[Rookery](https://github.com/aflock-ai/rookery) is a modular attestation framework that aflock builds on for cryptographic evidence generation and verification. It is a security-hardened fork of the [witness](https://witness.dev) project, maintained by [TestifySec](https://testifysec.com).

## What Rookery Does

Rookery generates **attestations** — cryptographic records that capture what happened during software supply chain activities:

- **Build provenance**: What was built, by whom, when, and how
- **Source metadata**: Git commit, branch, author information
- **Environment capture**: CI/CD context (GitHub Actions, GitLab CI, AWS CodeBuild)
- **Artifact tracking**: Input materials and output products with digests
- **Security scanning**: Secret detection, SBOM generation

These attestations are signed using DSSE envelopes and can be verified against policies to ensure supply chain integrity.

## How aflock Uses Rookery

aflock uses Rookery's attestation primitives to:

1. **Sign attestations** in the in-toto format with DSSE envelopes
2. **Verify signatures** against trusted functionaries (public keys, X.509 certificates, SPIFFE SVIDs)
3. **Manage signing keys** including SPIRE-based workload identity

The `attestation/`, `dsse/`, and `signer/` packages from Rookery provide aflock's cryptographic foundation.

## Plugin Architecture

Rookery uses a modular plugin system:

### Attestors (30+)

Plugins that generate attestation evidence:

| Category | Attestors |
|----------|-----------|
| **CI/CD** | GitHub Actions, GitLab CI, AWS CodeBuild, Jenkins |
| **Source** | Git metadata, commit info |
| **Runtime** | Command execution, environment capture |
| **Artifacts** | Material (inputs), Product (outputs) |
| **Security** | Secret scanning (Gitleaks), SBOM |
| **Container** | Docker image info, Kubernetes manifests |
| **Compliance** | SLSA provenance |

### Signers (8)

Plugins for cryptographic signing:

| Signer | Description |
|--------|-------------|
| **File** | Local key-based signing |
| **Fulcio** | Sigstore keyless signing |
| **SPIFFE** | Workload identity signing |
| **Vault** | HashiCorp Vault signing |
| **AWS KMS** | AWS Key Management Service |
| **Azure KMS** | Azure Key Management |
| **GCP KMS** | Google Cloud KMS |
| **Vault Transit** | Vault Transit engine |

## Security Hardening

Rookery includes fixes for security issues found in the upstream witness project, including certificate chain validation, symlink path traversal prevention, timestamp authority verification, and KMS offline verification hardening.

## Getting Started with Rookery

```bash
git clone https://github.com/aflock-ai/rookery.git
cd rookery
go work sync
make build
```

Rookery uses Go workspaces with each plugin as an independent module, allowing you to compose only the attestors and signers you need.

## Learn More

- [Rookery on GitHub](https://github.com/aflock-ai/rookery)
- [TestifySec](https://testifysec.com) — the company behind witness and rookery
- [witness.dev](https://witness.dev) — the upstream project
- [in-toto specification](https://in-toto.io/) — the attestation format standard
- [SLSA](https://slsa.dev/) — Supply-chain Levels for Software Artifacts
