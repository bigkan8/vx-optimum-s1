import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Core model settings
MODEL_SETTINGS = {
    "message_classifier": {
        "name": "optimum",
        "path": os.getenv("MODEL_PATH", "C:/Users/cyril/Downloads/optimum_model/optimum"),
        "max_length": 512
    }
}

# API configurations
API_CONFIG = {
    "openai": {
        "api_key": os.getenv("OPENAI_API_KEY"),
        "api_url": "https://api.openai.com/v1",  # Base URL without trailing slash
        "model": "o3-mini",  # Using o3-mini for generative tasks
        "timeout": 30
    },
    "perplexity": {
        "api_key": os.getenv("PERPLEXITY_API_KEY"),
        "api_url": "https://api.perplexity.ai",  # Base URL as per documentation
        "model": "sonar-reasoning-pro",  # Using sonar-reasoning-pro for fact checking
        "timeout": 60  # Increased timeout for fact verification
    },
    "pinecone": {
        "api_key": os.getenv("PINECONE_API_KEY"),
        "index_name": os.getenv("PINECONE_INDEX", "verifiedx"),
        "embedding_model": "text-embedding-3-small",
        "top_k": 1  # Number of similar results to return
    }
}

# URL processing settings
URL_SETTINGS = {
    "max_redirects": 5,
    "timeout": 10,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

# Analysis settings
ANALYSIS_SETTINGS = {
    "max_urls_to_check": 1,  # Currently we check first URL only
    "max_facts_to_check": 3  # Max facts to verify
}

class Settings:
    # API Keys from environment variables
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    PERPLEXITY_API_KEY = os.getenv("PERPLEXITY_API_KEY")
    MODEL_PATH = os.getenv("MODEL_PATH")
    PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
    PINECONE_INDEX = os.getenv("PINECONE_INDEX", "verifiedx")
    
    # API Settings
    API_HOST = "0.0.0.0"  # Allows connections from any IP
    API_PORT = 8000       # Standard port for development
    
    # Model Settings
    MAX_TEXT_LENGTH = 512  # Maximum text length for RoBERTa
    
    # URL Processing
    MAX_REDIRECT_DEPTH = 5  # Maximum number of URL redirects to follow
    URL_TIMEOUT = 10        # Timeout in seconds for URL requests
    
    @classmethod
    def validate(cls):
        """
        Validates that all required environment variables are set
        Raises ValueError if any are missing
        """
        required_vars = [
            "OPENAI_API_KEY", 
            "PERPLEXITY_API_KEY", 
            "MODEL_PATH",
            "PINECONE_API_KEY"
        ]
        missing = [var for var in required_vars if not getattr(cls, var)]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}") 