import pytest
from src.core.detector import Detector

@pytest.fixture
def detector():
    return Detector()

class TestDetector:
    @pytest.mark.asyncio
    async def test_analyze_phishing_message(self, detector):
        text = "URGENT: Verify your account now! Click: http://suspicious-site.com"
        result = await detector.analyze(text)
        
        assert "phishing" in result.lower()
        assert "suspicious" in result.lower()

    @pytest.mark.asyncio
    async def test_analyze_legitimate_message(self, detector):
        text = "Hey, check out this article on CNN: https://www.cnn.com/article"
        result = await detector.analyze(text)
        
        assert "legitimate" in result.lower()

    @pytest.mark.asyncio
    async def test_analyze_with_facts(self, detector):
        text = "Your bank account will be suspended. The Earth is flat."
        result = await detector.analyze(text)
        
        assert "misinformation" in result.lower()
        assert "suspicious" in result.lower()

    @pytest.mark.asyncio
    async def test_analyze_empty_message(self, detector):
        result = await detector.analyze("")
        assert "legitimate" in result.lower()

    @pytest.mark.asyncio
    async def test_analyze_multiple_urls(self, detector):
        text = "Check these: https://site1.com and https://site2.com"
        result = await detector.analyze(text)
        
        # Should analyze first URL as per settings
        assert "analyzed" in result.lower()

    @pytest.mark.asyncio
    async def test_error_handling(self, detector):
        result = await detector.analyze(None)
        assert "legitimate" in result.lower()  # Safe default 