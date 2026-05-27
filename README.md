# MCP Attest 🔐

[![CI](https://img.shields.io/github/actions/workflow/status/Carlos-Projects/mcp-attest/ci.yml?branch=main&logo=github)](https://github.com/Carlos-Projects/mcp-attest/actions)
[![PyPI version](https://img.shields.io/pypi/v/mcp-attest?logo=pypi)](https://pypi.org/project/mcp-attest/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/github/license/Carlos-Projects/mcp-attest?logo=opensourceinitiative)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-%3E80%25-brightgreen)](https://github.com/Carlos-Projects/mcp-attest)
[![GitHub stars](https://img.shields.io/github/stars/Carlos-Projects/mcp-attest?style=social)](https://github.com/Carlos-Projects/mcp-attest)

**Verify, trust, connect.** MCP Attest is a security extension for the Model Context Protocol that verifies server identity, integrity, and permissions before allowing a client to connect. Based on the paper [*Attested Tool-Server Admission*](https://arxiv.org/abs/2605.24248) (Alfredo Metere, May 2026).

---

## What it does 🎯

- **Identity Verification** — Verify MCP server identity via TLS certificates, cryptographic signatures, or DIDs
- **Integrity Attestation** — Generate and verify SHA-256 manifests of exposed server tools
- **Permission Auditing** — Evaluate requested vs declared permissions (least privilege principle)
- **Capability Fingerprinting** — Create unique server capability fingerprints to detect changes
- **Trust Score Calculation** — Calculate trust scores (0–100) based on identity, integrity, and permissions
- **Revocation Checking** — Verify if a server has been revoked from a trust list
- **Policy Generation** — Generate MCPGuard-compatible access policies based on trust scores

## What makes it unique 🏆

| Capability | What it does | Why it matters |
|---|---|---|
| **Multi-factor identity** | TLS certs + crypto signatures + DIDs | Defense in depth — no single point of trust |
| **Capability fingerprinting** | SHA-256 hash of exposed tools | Detect tool drift, tampering, or supply-chain attacks |
| **Trust scoring** | Weighted 0–100 score from 4 dimensions | Quantified risk decisions, not gut feelings |
| **MCPGuard integration** | Auto-generates access policies | Drop-in security for existing MCP deployments |

## Architecture 🏗️

```
┌──────────────┐     ┌──────────────────────────────────────────────┐
│   Client     │     │              MCP Attest CLI                   │
│  (MCP Host)  │     │                                              │
│              │     │  ┌─────────┐  ┌──────────┐  ┌─────────────┐  │
│  ┌────────┐  │     │  │Identity │  │Integrity │  │Permissions  │  │
│  │  Your  │  │────┼─▶│Verify   │──│Attest    │──│Audit        │  │
│  │  App   │  │     │  │(TLS/DID │  │(Manifest │  │(Least       │  │
│  └────────┘  │     │  │ /Crypto)│  │ /Fp)     │  │ Privilege)  │  │
│       │      │     │  └────┬────┘  └────┬─────┘  └──────┬──────┘  │
│       │      │     │       │            │               │         │
│       ▼      │     │       ▼────────────▼───────────────▼         │
│  ┌────────┐  │     │                   │                         │
│  │  MCP   │  │     │           ┌───────▼───────┐                 │
│  │ Server │  │     │           │ Trust Scorer  │                 │
│  └────────┘  │     │           │ (0–100 score) │                 │
└──────────────┘     │           └───────┬───────┘                 │
                     │                   │                         │
                     │           ┌───────▼───────┐                 │
                     │           │    Policy     │                 │
                     │           │   Generator   │──▶ MCPGuard     │
                     │           └───────────────┘                 │
                     └──────────────────────────────────────────────┘
```

## Quick Start ⚡

```bash
# Install from PyPI
pip install mcp-attest

# Or from source
git clone https://github.com/Carlos-Projects/mcp-attest
cd mcp-attest
pip install -e ".[dev]"

# Verify a server's identity, integrity, and trust
mcp-attest verify --server https://mcp.example.com --manifest manifest.json

# Generate a capability fingerprint
mcp-attest fingerprint --server https://mcp.example.com

# Calculate trust score
mcp-attest trust --server https://mcp.example.com

# Generate MCPGuard access policy
mcp-attest policy --server https://mcp.example.com --min-score 75
```

### Python API 🐍

```python
from mcp_attest import Attester

attester = Attester()
report = await attester.full_attestation(
    server_url="https://mcp.example.com",
)

print(f"Trust score: {report.trust.score}/100")
print(f"Identity: {'✅' if report.identity.verified else '❌'}")
print(f"Integrity: {report.integrity.status.value}")
```

## Comparison 📊

| Capability | **MCP Attest** | Raw MCP Client | mcp-scan |
|---|---|---|---|
| TLS identity verification | ✅ Multi-method | Basic | ❌ |
| Cryptographic signatures | ✅ RSA-2048 SHA-256 | ❌ | ❌ |
| DID verification | ✅ did:web + did:key | ❌ | ❌ |
| Capability fingerprinting | ✅ SHA-256 manifest hash | ❌ | ❌ |
| Trust scoring | ✅ Weighted (4 dimensions) | ❌ | ❌ |
| Permission auditing | ✅ Least privilege scoring | ❌ | ❌ |
| Revocation checking | ✅ Configurable lists | ❌ | ❌ |
| MCPGuard policy export | ✅ Auto-generate YAML | ❌ | ❌ |
| SARIF reporting | ✅ | ❌ | ✅ |

## Ecosystem 🔗

| Tool | Integration |
|---|---|
| [MCPGuard](https://github.com/Carlos-Projects/mcpguard) | Runtime policy enforcement middleware |
| [MCPscop](https://github.com/Carlos-Projects/mcpscope) | Dashboard visualization of attestation reports |
| [mcpwn](https://github.com/Carlos-Projects/mcpwn) | Offensive security testing against attestation baseline |
| [mcp-taxonomy](https://github.com/Carlos-Projects/mcp-taxonomy) | Canonical classification taxonomy for MCP security |

## Development 🛠️

```bash
pip install -e ".[dev]"
ruff check .
mypy src/mcp_attest/
pytest
```

## Academic References 📚

- [arXiv:2605.24248](https://arxiv.org/abs/2605.24248) — Attested Tool-Server Admission
- [arXiv:2605.25376](https://arxiv.org/abs/2605.25376) — KYA: Trust Layer for Autonomous Systems
- [MCP Specification](https://modelcontextprotocol.io/)
- [NIST AI RMF 1.0](https://www.nist.gov/itl/ai-risk-management-framework)
- [MITRE ATLAS](https://atlas.mitre.org/)

## License 📄

MIT — See [LICENSE](LICENSE) for details.
