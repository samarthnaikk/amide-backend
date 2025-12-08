# Amide - Network Traffic Analysis & Intrusion Detection System

Amide is a robust network monitoring and security solution that leverages machine learning to detect anomalies and potential threats in real-time network traffic. By combining local packet capture with cloud-based analysis, Amide provides a seamless experience for monitoring network health and security.

## Project Overview

The system is designed to capture network traffic from a client machine, analyze it using advanced machine learning models, and present actionable insights through a web dashboard.

### Key Features
- **Real-time Packet Capture**: Efficient C++ based agent for capturing and logging network traffic.
- **ML-Powered Analysis**: Utilizes LSTM and other models to detect anomalies and intrusion attempts.
- **Secure Authentication**: OTP-based signup and secure API key management.
- **Cloud-Native Architecture**: Scalable serverless backend and model hosting.

## Architecture

The project is composed of four distinct components working in harmony:

### 1. Frontend
- **Hosting**: Vercel (https://am4de.vercel.app)
- **Purpose**: A responsive web dashboard for users to visualize network traffic, view analysis reports, and manage their profile.

### 2. Backend API
- **Hosting**: Vercel (https://amide-backend.vercel.app)
- **Tech Stack**: Flask, Supabase (PostgreSQL), Redis
- **Purpose**: 
  - Manages user authentication (Signup, Signin, OTP verification).
  - Handles API key generation and validation.
  - Acts as an orchestration layer, receiving logs from the client and forwarding them to the model service.
  - Caches analysis results in Redis for performance.

### 3. Machine Learning Service
- **Hosting**: Hugging Face Spaces (https://samarthnaikk-amide-models.hf.space)
- **Purpose**: 
  - Hosts the inference engine for network analysis models (e.g., XGM_LSTM).
  - Processes raw network logs and returns classification results (Normal vs. Anomaly).

### 4. Internal Agent (NetInfo)
- **Environment**: Client Machine (Local)
- **Tech Stack**: C++, libpcap
- **Purpose**: 
  - Runs locally on the user's device.
  - Captures live network packets (Source/Dest IP, Ports, etc.).
  - Aggregates logs and periodically sends them to the backend for analysis.

## Workflow

1.  **Data Collection**: The **Internal Agent** captures network packets on the client machine and generates a log file.
2.  **Transmission**: The agent authenticates with the **Backend API** using a secure API key and uploads the logs.
3.  **Analysis**: The Backend forwards the data to the **ML Service** on Hugging Face.
4.  **Inference**: The ML model processes the logs and identifies patterns or anomalies.
5.  **Result**: The analysis is returned to the Backend, cached in Redis, and made available to the **Frontend** for display.

## Setup & Deployment

- **Backend**: Deployed automatically via Vercel. Requires `SUPABASE_URL`, `REDIS_HOST`, and Google OAuth credentials.
- **Models**: Deployed on Hugging Face Spaces as a Dockerized Python application.
- **Agent**: Compiled locally using `g++` and `libpcap`.

---
*Built for security, powered by AI.*