---
sidebar_position: 1
---

# TestifySec

[TestifySec](https://testifysec.com) is the company behind aflock and rookery. TestifySec builds tools for software supply chain security, focusing on cryptographic attestation, policy enforcement, and compliance automation.

## Projects

| Project | Description | Link |
|---------|-------------|------|
| **aflock** | Cryptographically signed policies for AI agent execution | [GitHub](https://github.com/aflock-ai/aflock) |
| **cilock** | CI/CD attestation wrapper for GitHub Actions and GitLab CI | [GitHub](https://github.com/aflock-ai/cilock-action) |
| **Rookery** | Modular attestation framework (witness fork) | [GitHub](https://github.com/aflock-ai/rookery) |
| **Witness** | Supply chain attestation and verification | [witness.dev](https://witness.dev) |

## How the Projects Relate

| Layer | Project | Role |
|-------|---------|------|
| **AI Agent Security** | [aflock](https://github.com/aflock-ai/aflock) | AI agent policy enforcement — constrains what agents can do |
| **CI/CD Security** | [cilock](https://github.com/aflock-ai/cilock-action) | CI/CD pipeline attestation — prevents supply chain attacks in builds |
| **Attestation** | [Rookery](https://github.com/aflock-ai/rookery) | Cryptographic evidence generation — signs and verifies attestations |
| **Foundation** | [Witness](https://witness.dev) | Supply chain attestation framework — the upstream project Rookery forks |

**Witness** provides the foundational supply chain attestation framework. **Rookery** is a security-hardened, modular fork with a plugin architecture. **cilock** uses Rookery to wrap CI/CD pipeline steps with cryptographic attestation, providing defense against supply chain attacks like the [Trivy](https://testifysec.com/blog/cilock-action-supply-chain-attacks) and [LiteLLM](https://testifysec.com/blog/cilock-litellm-supply-chain-attack) compromises of March 2026. **aflock** extends Rookery's attestation primitives to constrain AI agent behavior with signed policies.

## Contact

- Website: [testifysec.com](https://testifysec.com)
- Security issues: cole@testifysec.com
