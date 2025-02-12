import sys
import os
from pathlib import Path
import logging

# Configure logging with more detail
logging.basicConfig(
    level=logging.INFO,  # Changed from DEBUG to INFO to reduce noise
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout  # Explicitly write to stdout
)

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.core.detector import Detector
import asyncio

def preprocess_text(text: str) -> str:
    """
    Preprocess input text to ensure consistent format:
    1. Replace multiple newlines with single space
    2. Replace multiple spaces with single space
    3. Strip leading/trailing whitespace
    4. Handle special characters if needed
    """
    logging.debug(f"Preprocessing text: {text}")
    
    # Replace newlines and carriage returns with space
    text = text.replace('\n', ' ').replace('\r', ' ')
    
    # Replace multiple spaces with single space
    text = ' '.join(text.split())
    
    # Strip leading/trailing whitespace
    text = text.strip()
    
    logging.debug(f"Preprocessed text: {text}")
    return text

async def analyze_message(message: str):
    try:
        logging.info("Starting message analysis")
        
        # Preprocess the input text
        processed_message = preprocess_text(message)
        logging.info(f"Processed message: {processed_message}")
        
        detector = Detector()
        logging.info("Created detector instance")
        
        result = await detector.analyze(processed_message)
        logging.info("Analysis completed")
        
        # Print a clear separator before the actual output
        print("\n" + "="*80)
        print("PHISHING ANALYSIS RESULTS")
        print("="*80)
        print(f"\nAnalyzing message:\n{message}")
        print("\n" + "-"*80)
        print("ANALYSIS OUTPUT:")
        print("-"*80)
        print(f"\n{result}\n")
        print("="*80 + "\n")
        return result
        
    except Exception as e:
        logging.error(f"Error in analyze_message: {str(e)}", exc_info=True)
        raise

if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            message = " ".join(sys.argv[1:])
            logging.info(f"Received message: {message}")
            asyncio.run(analyze_message(message))
        else:
            print("Please provide a message to analyze.")
            print("Usage: python analyze.py \"your message here\"")
            sys.exit(1)
    except Exception as e:
        logging.error(f"Main execution error: {str(e)}", exc_info=True)
        sys.exit(1) 