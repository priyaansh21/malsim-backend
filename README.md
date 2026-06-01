# MalSim Enterprise Malware Analysis Platform

## Overview

MalSim Enterprise Malware Analysis Platform is a comprehensive cybersecurity solution designed to automate malware inspection, threat classification, forensic analysis, and security intelligence generation. The platform enables security analysts, researchers, and incident response teams to safely analyze suspicious files through static analysis, dynamic behavior analysis, YARA rule matching, and network activity monitoring.

The system provides centralized malware investigation workflows, detailed threat reports, risk scoring, and historical analysis management through a secure web-based interface powered by FastAPI.

---

## Features

### Static Malware Analysis
- File metadata extraction
- SHA256, MD5, and SHA1 hash generation
- File signature identification
- Entropy analysis
- String extraction
- PE file inspection
- Imported API detection
- Suspicious indicator discovery

### Dynamic Malware Analysis
- Runtime behavior monitoring
- Process activity tracking
- Registry modification detection
- File system activity monitoring
- Persistence mechanism detection
- Behavioral profiling

### Threat Detection
- YARA rule scanning
- Malware family identification
- Signature-based detection
- Threat intelligence correlation
- Indicator of Compromise (IOC) extraction

### Network Analysis
- IP communication monitoring
- Domain analysis
- DNS request inspection
- Suspicious connection detection
- Traffic anomaly identification
- Command-and-Control (C2) communication detection

### Reporting & Analytics
- Comprehensive malware reports
- Risk score generation
- Threat classification
- Historical investigation tracking
- Security analytics dashboard
- Incident response support

### Database Management
- SQLite-based storage
- Malware sample management
- Analysis history retention
- Investigation logs
- Audit trail maintenance

---

## Technology Stack

### Backend
- FastAPI
- Uvicorn
- SQLAlchemy
- SQLite
- Pydantic

### Security & Analysis
- YARA
- Python Malware Analysis Libraries
- Threat Intelligence Frameworks

### Data Processing
- Python
- AioSQLite
- File Hashing Algorithms
- Behavioral Analysis Engines

---

## System Architecture

```text
Suspicious File
       │
       ▼
File Upload Module
       │
       ▼
Static Analysis Engine
       │
       ▼
Dynamic Analysis Engine
       │
       ▼
YARA Detection Engine
       │
       ▼
Network Analysis Module
       │
       ▼
Threat Classification
       │
       ▼
Risk Assessment Engine
       │
       ▼
Database Storage
       │
       ▼
Analysis Report Dashboard
```

---

## Installation

### Clone Repository

```bash
git clone https://github.com/priyaansh21/YOUR-REPOSITORY-NAME.git
cd YOUR-REPOSITORY-NAME
```

### Create Virtual Environment

```bash
python -m venv .venv
```

### Activate Environment

#### Windows

```bash
.venv\Scripts\activate
```

#### Linux / macOS

```bash
source .venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Running the Application

Start the FastAPI server:

```bash
uvicorn main:app --reload
```

Application URL:

```text
http://127.0.0.1:8000
```

API Documentation:

```text
http://127.0.0.1:8000/docs
```

Alternative Documentation:

```text
http://127.0.0.1:8000/redoc
```

---

## API Capabilities

### File Analysis

```http
POST /upload
```

Upload suspicious files for analysis.

### Retrieve Analysis Results

```http
GET /analysis/{id}
```

View detailed malware analysis reports.

### Threat History

```http
GET /history
```

Retrieve previous investigations and reports.

### Risk Assessment

```http
GET /risk-score/{id}
```

View generated threat severity scores.

---

## Risk Levels

| Score Range | Threat Level |
|------------|-------------|
| 0 - 25 | Low |
| 26 - 50 | Medium |
| 51 - 75 | High |
| 76 - 100 | Critical |

---

## Key Skills Demonstrated

- Cybersecurity
- Malware Analysis
- Digital Forensics
- Threat Detection
- Threat Intelligence
- YARA Rule Development
- Static Analysis
- Dynamic Analysis
- Network Traffic Analysis
- Risk Assessment
- Security Analytics
- FastAPI Development
- REST API Design
- Database Management
- Incident Response

---

## Project Outcomes

- Automated malware investigation workflow
- Faster threat identification and classification
- Improved incident response efficiency
- Centralized threat intelligence management
- Detailed forensic reporting capabilities
- Scalable architecture for future enhancements
- Enhanced cybersecurity monitoring and analysis

---

## Future Enhancements

- VirusTotal Integration
- SIEM Integration
- Sandbox Execution Environment
- Machine Learning-Based Threat Detection
- Real-Time Threat Intelligence Feeds
- Automated IOC Correlation
- Multi-User Role Management
- Advanced Security Dashboard

---

## Author

**Priyaansh Jaiswal**

B.Tech (Hons.) Computer Science Engineering  
RV University, Bangalore

Cybersecurity | AI Security | Threat Intelligence | Malware Analysis
