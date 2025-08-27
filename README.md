# Infra AI Backend

## Overview
This project implements an automated incident resolution system that integrates AWS, Supabase, Google Gemini, and Infisical to provide intelligent infrastructure management.

## Architecture
The system follows a structured workflow:
1. Polls AWS SQS for incoming incidents
2. Retrieves system information from Supabase CMDB
3. Uses Google Gemini for AI-powered diagnostics and resolution planning
4. Executes resolution steps via SSH
5. Updates incident status in Supabase

## Key Components
- **worker.py**: Core implementation of the incident resolution workflow
- **main.py**: Entry point for local development
- **.env**: Environment configuration file
- **requirements.txt**: Python dependencies

## Security Features
- Sensitive data redaction in logs
- Temporary SSH key management with strict permissions
- Structured error handling with stack trace capture

## Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Set appropriate values in .env
```

## Usage
```bash
# For local development
python main.py

# For production worker
python worker.py
```

## Integration Points
- **AWS**: SQS for message queue, EC2 for instance management
- **Supabase**: CMDB and incident tracking
- **Infisical**: Secure SSH key retrieval
- **Google Gemini**: AI diagnostics and resolution planning

## License
MIT License
