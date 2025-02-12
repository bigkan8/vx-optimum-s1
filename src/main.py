import uvicorn
from api.routes import app
from config.settings import Settings

def main():
    # Validate settings
    Settings.validate()
    
    # Run the API server
    uvicorn.run(
        "api.routes:app",
        host=Settings.API_HOST,
        port=Settings.API_PORT,
        reload=True  # Enable auto-reload during development
    )

if __name__ == "__main__":
    main() 