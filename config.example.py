"""
Scenario2Caldera Configuration Example

Copy this file to config.py and customize your settings.
Or use .env file for environment variables.
"""

# Caldera C2 Configuration
CALDERA_CONFIG = {
    "url": "http://192.168.50.31:8888",
    "api_key": "ADMIN123",  # Change this to your Caldera API key
    "timeout": 30
}

# LLM Configuration (Ollama)
LLM_CONFIG = {
    "model": "gpt-oss:120b",  # or "qwen2.5:32b", "llama3.1:70b", etc.
    "host": "http://192.168.50.252:11434",
    "api_key": None,
    "temperature": 0.1,
    "timeout": 60
}

# Directories
SCENARIOS_DIR = "scenarios"
RESULTS_DIR = "results"
LOGS_DIR = "logs"
