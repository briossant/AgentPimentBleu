# Use Python 3.10 slim as the base image
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    nodejs \
    npm && \
    npm install -g npm@9.6.7 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy requirements.txt and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create cache directory for models
RUN mkdir -p /app/.cache/agentpimentbleu/models

# Copy the application code
COPY . .

# Expose port for Gradio
EXPOSE 7860

# Create volume for model cache
VOLUME /app/.cache/agentpimentbleu/models

# Set environment variable for cache directory
ENV APB_RAG_SETTINGS__CACHE_DIR="/app/.cache/agentpimentbleu/models"

# Set the command to run the Gradio app
CMD ["python", "main.py"]
