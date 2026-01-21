# SecDetect AI

🛡️ **A GenAI-Powered Detection Engineering Platform**

A full-stack security operations platform demonstrating detection-as-code, alert enrichment, GenAI-powered analysis, and SlackOps workflows.

![Dashboard](https://img.shields.io/badge/Frontend-React-blue)
![Backend](https://img.shields.io/badge/Backend-FastAPI-green)
![AI](https://img.shields.io/badge/AI-Claude-purple)
![Docker](https://img.shields.io/badge/Docker-Ready-blue)

## 🎯 Features

| Component | Description |
|-----------|-------------|
| **Detection-as-Code** | Sigma-style YAML detection rules with automated evaluation |
| **Alert Enrichment** | Automatic context from threat intel, asset inventory, and user history |
| **GenAI Analysis** | Claude-powered security analysis and investigation assistance |
| **SlackOps Bot** | Real-time security operations directly from Slack |
| **React Dashboard** | Professional dark-themed UI for security operations |
| **Testing Framework** | Comprehensive pytest suite with 15+ test cases |
| **Docker Support** | Fully containerized deployment |

## 🖥️ Screenshots

### Dashboard
- System status monitoring
- Detection rules overview
- Real-time alerts

### Detection Engine
- Run detections against login events
- MITRE ATT&CK mapping
- Severity classification

### Alert Enrichment
- User context (department, role, device)
- IP threat intelligence
- Risk score calculation (0-100)

### AI Analysis
- Natural language security analysis
- IOC classification
- Recommended actions

## 🚀 Quick Start

### Option 1: Docker (Recommended)
```bash
# Clone the repository
git clone https://github.com/iojini/secdetect-ai.git
cd secdetect-ai

# Configure environment
cp .env.example .env
# Edit .env with your API keys

# Run with Docker
docker-compose up --build
```

Access the app at `http://localhost:3000`

### Option 2: Manual Setup

#### Prerequisites
- Python 3.12+
- Node.js 20+
- Slack workspace with bot permissions
- Anthropic API key (for GenAI features)

#### Backend Setup
```bash
# Clone the repository
git clone https://github.com/iojini/secdetect-ai.git
cd secdetect-ai

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys

# Run the backend
uvicorn main:app --reload
```

#### Frontend Setup
```bash
# In a new terminal
cd frontend
npm install
npm start
```

Access the app at `http://localhost:3000`

### Running the Slack Bot
```bash
# With virtual environment activated
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

## 🌐 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | System status |
| `/api/rules` | GET | List detection rules |
| `/api/detect` | POST | Run detection |
| `/api/enrich` | POST | Enrich alert |
| `/api/analyze` | POST | AI analysis |

## 📁 Project Structure
```
secdetect-ai/
├── main.py                 # FastAPI backend
├── slack_bot.py            # Slack bot with all commands
├── detection_engine.py     # Sigma-style detection engine
├── enrichment_engine.py    # Alert enrichment with threat intel
├── test_detections.py      # Pytest test suite
├── requirements.txt        # Python dependencies
├── Dockerfile              # Backend container
├── docker-compose.yml      # Multi-container setup
├── detections/
│   └── rules/
│       └── suspicious_login.yml
├── frontend/
│   ├── Dockerfile          # Frontend container
│   ├── src/
│   │   ├── App.js          # React dashboard
│   │   └── App.css         # Styling
│   └── package.json
├── .env                    # API keys (not in repo)
├── .env.example            # Environment template
└── README.md
```

## 🧪 Test Coverage

- ✅ Detection rule loading and validation
- ✅ False positive testing (business hours)
- ✅ True positive testing (off-hours)
- ✅ Boundary condition testing (6 AM, 10 PM)
- ✅ User enrichment accuracy
- ✅ Malicious IP detection
- ✅ Risk score calculation
- ✅ Full pipeline integration

## 🔧 Technologies Used

- **Backend:** Python, FastAPI, Uvicorn
- **Frontend:** React, Axios
- **AI:** Anthropic Claude API
- **Bot:** Slack Bolt
- **Testing:** pytest
- **Containers:** Docker, Docker Compose
- **Detection:** PySigma, YAML

## 🔒 Security Note

Never commit your `.env` file. It contains sensitive API keys. Use `.env.example` as a template.

## 📄 License

MIT License - feel free to use and modify.

## 👤 Author

Built as a portfolio project demonstrating detection engineering, GenAI integration, and full-stack development skills.

---

⭐ If you found this useful, please star the repository!