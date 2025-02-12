import pytest
import os
import asyncio
from src.core.detector import Detector

@pytest.mark.asyncio
async def test_mixed_case():
    try:
        detector = Detector()
        
        # Test input with both URL and facts
        test_input = """Hey, I just read this important security update from Microsoft: https://www.microsoft.com/en-us/security/2024/update
        
        According to their announcement:
        1. All Windows 10 systems need immediate patching
        2. The update fixes a critical vulnerability affecting 85% of systems
        3. Users have only 24 hours to apply the patch
        
        Please verify your system and update ASAP to avoid account suspension."""

        # Clear formatting
        print("\n")
        print("╔" + "═"*78 + "╗")
        print("║" + " "*30 + "TEST INPUT" + " "*37 + "║")
        print("╠" + "═"*78 + "╣")
        for line in test_input.split('\n'):
            print("║ " + line.ljust(76) + " ║")
        print("╚" + "═"*78 + "╝")

        # Run the analysis with timeout
        try:
            result = await asyncio.wait_for(
                detector.analyze(test_input),
                timeout=120  # 2 minute timeout
            )
            
            print("\n")
            print("╔" + "═"*78 + "╗")
            print("║" + " "*28 + "ANALYSIS RESULT" + " "*35 + "║")
            print("╠" + "═"*78 + "╣")
            # Split result into lines and format each line
            for line in result.split('\n'):
                # Handle long lines by wrapping them
                while len(line) > 76:
                    print("║ " + line[:76] + " ║")
                    line = line[76:]
                print("║ " + line.ljust(76) + " ║")
            print("╚" + "═"*78 + "╝\n")
            
        except asyncio.TimeoutError:
            pytest.fail("Test timed out after 120 seconds")
        except Exception as e:
            pytest.fail(f"Analysis failed with error: {str(e)}")
        
        # Verify the result structure
        assert isinstance(result, str), "Result should be a string"
        # Check for any of the possible verdict indicators
        has_verdict = any(phrase in result.lower() for phrase in [
            "final determination",
            "bottom line",
            "verdict",
            "analysis result"
        ])
        assert has_verdict, "Result should contain a verdict"
        
        # The message should be detected as phishing because:
        # 1. Uses urgency and pressure tactics
        # 2. Threatens account suspension
        # 3. Makes specific claims about Windows systems that need verification
        
        assert "phishing" in result.lower(), "This should be detected as phishing"
        
        return result

    except Exception as e:
        pytest.fail(f"Test failed with error: {str(e)}")

@pytest.mark.asyncio
async def test_custom_message():
    """Test the detector with a custom message from environment variable"""
    message = os.getenv("PHISHING_TEST_MESSAGE")
    if not message:
        pytest.skip("No test message provided. Set PHISHING_TEST_MESSAGE environment variable to test.")
        
    try:
        detector = Detector()
        result = await asyncio.wait_for(
            detector.analyze(message),
            timeout=120  # 2 minute timeout
        )
        print(f"\nAnalyzing message:\n{message}\n")
        print(f"\nComplete analysis result:\n{result}\n")
        return result
    except asyncio.TimeoutError:
        pytest.fail("Test timed out after 120 seconds")
    except Exception as e:
        pytest.fail(f"Test failed with error: {str(e)}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        # If message provided, set it as environment variable
        os.environ["PHISHING_TEST_MESSAGE"] = " ".join(sys.argv[1:])
        pytest.main(["-v", "-s", __file__, "-k", "test_custom_message"])
    else:
        pytest.main(["-v", "-s", __file__, "-k", "test_mixed_case"]) 