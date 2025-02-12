import pytest
from src.core.url_analyzer import URLAnalyzer

@pytest.fixture
def analyzer():
    return URLAnalyzer()

class TestURLAnalyzer:
    @pytest.mark.asyncio
    async def test_analyze_suspicious_url(self, analyzer):
        url = "http://suspicious-banking-site.com/login"
        result = await analyzer.analyze(url)
        
        assert result["is_suspicious"] == True
        assert "risk_factors" in result
        assert len(result["risk_factors"]) > 0

    @pytest.mark.asyncio
    async def test_analyze_legitimate_url(self, analyzer):
        url = "https://www.google.com"
        result = await analyzer.analyze(url)
        
        assert result["is_suspicious"] == False
        assert len(result["risk_factors"]) == 0

    @pytest.mark.asyncio
    async def test_analyze_malformed_url(self, analyzer):
        url = "not-a-real-url"
        result = await analyzer.analyze(url)
        
        assert "error" in result
        assert result["is_suspicious"] == True  # Safe default

    @pytest.mark.asyncio
    async def test_analyze_empty_url(self, analyzer):
        result = await analyzer.analyze("")
        assert "error" in result 