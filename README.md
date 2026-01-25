# GuardAI (Demo) – AI Attack Prevention Gateway

This repo contains a simple demo architecture:
- github-gateway: receives requests for GitHub code search, runs policy engine, then (in real life) calls GitHub API
- policy-engine: evaluates rules.yaml and returns ALLOW/BLOCK decisions
- llm-proxy: a minimal "agent firewall" that blocks dangerous tool calls and enforces allowlists

## Run locally

### 1) GitHub gateway
cd github-gateway
python -m venv .venv
. .venv/bin/activate  # (Windows: .venv\Scripts\activate)
pip install -r requirements.txt
python app.py

Health: http://localhost:8001/health

### 2) LLM proxy
cd ../llm-proxy
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python proxy.py

Health: http://localhost:8002/health

## Test
POST http://localhost:8001/github/search_code
{
  "parameters": {"query": "repo:myorg/myrepo password", "max_results": 5}
}

Expected: 403 blocked
