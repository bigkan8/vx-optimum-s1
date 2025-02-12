import pytest
from src.core.detector import PhishingDetector

@pytest.fixture
def detector():
    return PhishingDetector()

@pytest.mark.asyncio
async def test_analyze_url_only():
    detector = PhishingDetector()
    result = await detector.analyze("http://example.com")
    assert isinstance(result.is_phishing, bool)
    assert isinstance(result.confidence, float)
    assert result.explanation 