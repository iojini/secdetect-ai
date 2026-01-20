# SecDetect AI

🛡️ **An Open-Source GenAI-Powered Detection Engineering Platform**

A Python-based security operations platform demonstrating detection-as-code, alert enrichment, GenAI-powered analysis, and SlackOps workflows.

## 🎯 Features

| Component | Description |
|-----------|-------------|
| **Detection-as-Code** | Sigma-style YAML detection rules with automated evaluation |
| **Alert Enrichment** | Automatic context from threat intel, asset inventory, and user history |
| **GenAI Analysis** | Claude-powered security analysis and investigation assistance |
| **SlackOps Bot** | Real-time security operations directly from Slack |
| **Testing Framework** | Comprehensive pytest suite with 15+ test cases |

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- Slack workspace with bot permissions
- Anthropic API key (for GenAI features)

### Installation
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/secdetect-ai.git
cd secdetect-ai

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install fastapi uvicorn slack-bolt python-dotenv pydantic requests anthropic pysigma pytest

# Configure environment
cp .env.example .env
# Edit .env with your API keys
```

### Running the Bot
```bash
python slack_bot.py
```

### Running Tests
```bash
pytest test_detections.py -v
```

## 💬 Slack Commands

| Command | Description |
|---------|-------------|
| `hello` | Greeting and status check |
| `status` | System status with loaded rules count |
| `rules` | List all loaded detection rules |
| `detect login <user> <hour>` | Run detection on a login event |
| `enrich <user> <ip>` | Enrich an alert with context |
| `analyze <IOC>` | AI-powered security analysis |

## 📁 Project Structure
```
secdetect-ai/
├── main.py                 # FastAPI backend
├── slack_bot.py            # Slack bot with all commands
├── detection_engine.py     # Sigma-style detection engine
├── enrichment_engine.py    # Alert enrichment with threat intel
├── test_detections.py      # Pytest test suite
├── detections/
│   └── rules/
│       └── suspicious_login.yml
├── .env                    # API keys (not in repo)
└── README.md
```

## 🧪 Test Coverage

- Detection rule loading and validation
- False positive testing (business hours)
- True positive testing (off-hours)
- Boundary condition testing
- Enrichment accuracy
- Risk score calculation
- Full pipeline integration

## 🔒 Security Note

Never commit your `.env` file. It contains sensitive API keys.

## 📄 License

MIT License - feel free to use and modify.

## 👤 Author

Built as a portfolio project demonstrating detection engineering and GenAI integration skills.
```