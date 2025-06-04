"""
AgentPimentBleu - API Main

This module defines the FastAPI application.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agentpimentbleu.api.routers import scan
from agentpimentbleu.config.config import get_settings
from agentpimentbleu.utils.logger import get_logger

logger = get_logger()

# Get the application configuration
app_config = get_settings()

# Create the FastAPI app
app = FastAPI(
    title="AgentPimentBleu API",
    description="API for the AgentPimentBleu security scanner",
    version="0.1.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, this should be restricted
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan.router, prefix="/scan", tags=["scan"])


@app.get("/")
async def root():
    """
    Root endpoint.
    
    Returns:
        dict: A welcome message
    """
    return {
        "message": "Welcome to AgentPimentBleu API",
        "docs_url": "/docs",
        "redoc_url": "/redoc"
    }


@app.get("/health")
async def health():
    """
    Health check endpoint.
    
    Returns:
        dict: The health status
    """
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)