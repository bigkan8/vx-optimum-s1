import asyncio
from src.core.detector import Detector

async def test_messages():
    print("\n=== Starting Phishing Detection System ===\n")
    
    detector = Detector()
    
    test_cases = [
        # Obvious phishing
        "URGENT: Your account has been suspended! Verify now: http://suspicious-bank.com/verify",
        
        # Legitimate message
        "Hey, check out this interesting article on CNN: https://www.cnn.com/2024/tech-news",
        
        # Phishing with misinformation
        "Due to the recent solar flare, all bank accounts need verification. Click here: http://secure-verify.net",
        
        # Normal message
        "Here's that document we discussed in the meeting: https://docs.google.com/spreadsheets"
    ]
    
    for i, message in enumerate(test_cases, 1):
        print(f"\nTest Case {i}:")
        print(f"Message: {message}")
        print("\nAnalyzing...")
        
        result = await detector.analyze(message)
        
        print(f"\nResult:\n{result}")
        print("\n" + "="*80)

if __name__ == "__main__":
    asyncio.run(test_messages()) 