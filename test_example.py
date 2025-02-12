import asyncio
import logging
import pinecone

# Assuming the updated code is properly installed or available in your PYTHONPATH
# For example, from your 'analyze.py' or the 'Detector' and 'OutputGenerator' classes:
from verifiedx.analyze import analyze_message

logging.basicConfig(level=logging.INFO)

async def main():
    # Provide a test message that includes both normal text and a suspicious URL
    test_input_text = "Check out this suspicious link: http://bit.ly/fakesite"
    result = await analyze_message(test_input_text)

    print("\n===== TEST RESULT =====")
    print(result)

    # Then call pinecone.init, create_index, etc.
    pinecone.init(api_key="your-key", environment="us-west1-gcp")  # Example environment

if __name__ == "__main__":
    asyncio.run(main()) 