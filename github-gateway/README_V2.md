# GuardAI 2.0 🛡️

**AI-powered runtime security for Agentic AI systems**

 multi-tier approach to protecting LLMs and AI agents from prompt injection, jailbreaks, and data exfiltration.

---

## 🆕 What's New in 2.0

### 🎯 3-Tier Security Architecture

GuardAI 2.0 implements a sophisticated defense-in-depth strategy.



### ✨ Key Features

- **🤖 AI Judge (LLM-as-a-Judge)**: Context-aware security decisions using LLM
- **🔑 BYOK Support**: Bring Your Own Key - separate policy API keys
- **📊 Suspicion Scoring**: Heuristic-based intelligent routing (0-100 scale)
- **🎯 Smart Invocation**: Only calls AI when needed (cost optimization)
- **📝 Immutable Logging**: Full audit trail with attack path reconstruction
- **🔄 Fail-Safe Modes**: Configurable fail-open/fail-closed per tool risk
- **💾 Training Data Collection**: Auto-collects samples for ML/Fine-tuning
- **⚡ Performance**: Caching + de-duplication for speed

---

## 🏗️ Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed architecture documentation.

### Component Overview



---

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.9+
pip install -r requirements.txt

# Install LLM providers (choose one or both)
pip install groq openai




