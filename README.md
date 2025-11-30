# Agents Explainability

A repository dedicated to AI agent explainability, transparency, and governance. This project explores production-grade patterns for building auditable, compliant, and trustworthy multi-agent systems.

## Overview

As AI agents become increasingly autonomous—making decisions, invoking tools, and collaborating with other agents—the need for **explainability** has never been greater. This repository provides:

- **Deep-dive articles** on agent explainability patterns and practices
- **Production-grade frameworks** for output validation and PII protection
- **Real-world case studies** from fintech and enterprise deployments
- **Practical tools** for managing and sharing explainability documentation

## Repository Structure

```
agents-explainability/
├── articles/                          # In-depth articles and guides
│   └── guardrails_validation_deepdive.md
├── scripts/                           # Utility tools
│   ├── gist_manager.py                # GitHub gist management tool
│   └── GIST_MANAGER_README.md         # Gist manager documentation
└── README.md                          # This file
```

## Quick Start

### Clone the Repository

```bash
git clone git@github.com:rajnishkhatri/agents-explainability.git
cd agents-explainability
```

### HTTPS Alternative

```bash
git clone https://github.com/rajnishkhatri/agents-explainability.git
cd agents-explainability
```

## Featured Content

### GuardRails: The Security Checkpoint for AI Agents

**Location:** [`articles/guardrails_validation_deepdive.md`](articles/guardrails_validation_deepdive.md)

A comprehensive deep dive into production-grade output validation and PII protection for AI agents. This article covers:

- **The PII Leak Incident**: Real-world case study from a fintech deployment
- **TSA Security Model**: Applying airport security principles to agent outputs
- **GuardRails Framework**: Declarative validation system for agent outputs
- **Production Patterns**: Implementation strategies for regulatory compliance
- **Code Examples**: Practical Python implementations

**Key Topics:**
- Output validation at agent boundaries
- PII detection and redaction
- Declarative validator patterns
- Multi-agent security checkpoints
- Regulatory compliance (HIPAA, SOX, GDPR)

## Tools

### GitHub Gist Manager

A command-line tool for creating and managing GitHub gists from local files. Useful for sharing articles, code snippets, and documentation.

**Setup:**
1. Get a GitHub Personal Access Token with `gist` scope
2. Add to your `.env` file: `GITHUB_TOKEN=your_token_here`
3. Install dependencies: `pip install requests rich python-dotenv`

**Usage:**
```bash
# Create a public gist from an article
python scripts/gist_manager.py create articles/guardrails_validation_deepdive.md \
  --description "GuardRails Validation Deep Dive" \
  --public

# List all your gists
python scripts/gist_manager.py list

# Update an existing gist
python scripts/gist_manager.py update <gist_id> articles/guardrails_validation_deepdive.md
```

See [`scripts/GIST_MANAGER_README.md`](scripts/GIST_MANAGER_README.md) for complete documentation.

## Four Pillars of Agent Explainability

This repository is organized around four core pillars of agent explainability:

1. **Recording** (What happened?) - Flight recorder patterns for event capture
2. **Identity** (Who did it?) - Agent metadata and capability declarations
3. **Validation** (Was it correct?) - Output validation and safety checks
4. **Reasoning** (Why did it happen?) - Decision logging and rationale capture

The GuardRails article focuses on **Validation** - ensuring agent outputs meet safety, compliance, and quality standards before they reach downstream systems or end users.

## Use Cases

- **Fintech**: Fraud detection, loan processing, compliance auditing
- **Healthcare**: Patient data protection, diagnostic decision tracking
- **Enterprise**: Multi-tenant governance, cost attribution, audit trails
- **Research**: Reproducible agent workflows, decision transparency

## Contributing

Contributions are welcome! Areas of interest:

- Additional explainability patterns and case studies
- Implementation examples in different frameworks
- Regulatory compliance guides for specific industries
- Tools and utilities for agent observability

## Related Resources

- **AgentRxiv**: Research on agent explainability patterns
- **Guardrails AI**: Declarative validation framework
- **BlackBox Recording**: Event capture patterns
- **AgentFacts**: Agent metadata standards

## License

This repository contains educational content and practical examples. Please review individual articles for specific licensing information.

## Contact

For questions, suggestions, or collaboration opportunities, please open an issue on GitHub.

---

**Repository:** [github.com/rajnishkhatri/agents-explainability](https://github.com/rajnishkhatri/agents-explainability)

**Last Updated:** November 2024
