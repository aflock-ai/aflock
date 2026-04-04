---
sidebar_position: 1
---

# TestifySec

[TestifySec](https://testifysec.com) is the company behind aflock and rookery. TestifySec builds tools for software supply chain security, focusing on cryptographic attestation, policy enforcement, and compliance automation.

## Projects

| Project | Description | Link |
|---------|-------------|------|
| **aflock** | Cryptographically signed policies for AI agent execution | [GitHub](https://github.com/aflock-ai/aflock) |
| **Rookery** | Modular attestation framework (witness fork) | [GitHub](https://github.com/aflock-ai/rookery) |
| **Witness** | Supply chain attestation and verification | [witness.dev](https://witness.dev) |

## How the Projects Relate

| Layer | Project | Role |
|-------|---------|------|
| **Application** | [aflock](https://github.com/aflock-ai/aflock) | AI agent policy enforcement — constrains what agents can do |
| **Attestation** | [Rookery](https://github.com/aflock-ai/rookery) | Cryptographic evidence generation — signs and verifies attestations |
| **Foundation** | [Witness](https://witness.dev) | Supply chain attestation framework — the upstream project Rookery forks |

**Witness** provides the foundational supply chain attestation framework. **Rookery** is a security-hardened, modular fork with a plugin architecture. **aflock** extends Rookery's attestation primitives to constrain AI agent behavior with signed policies.

## Contact

- Website: [testifysec.com](https://testifysec.com)
- Security issues: cole@testifysec.com
