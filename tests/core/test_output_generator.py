import pytest
from src.core.output_generator import OutputGenerator

@pytest.fixture
def generator():
    return OutputGenerator()

class TestOutputGenerator:
    @pytest.mark.asyncio
    async def test_generate_output_phishing(self, generator):
        message_analysis = {"is_phishing": True, "confidence": 0.9}
        url_analysis = {"is_suspicious": True, "risk_factors": ["suspicious_domain"]}
        fact_results = {"contains_misinformation": False}
        
        result = await generator.generate_output(
            "Check this site!",
            message_analysis,
            url_analysis,
            fact_results
        )
        
        assert "suspicious" in result.lower()
        assert "phishing" in result.lower()

    @pytest.mark.asyncio
    async def test_generate_output_legitimate(self, generator):
        message_analysis = {"is_phishing": False, "confidence": 0.9}
        url_analysis = {"is_suspicious": False, "risk_factors": []}
        fact_results = {"contains_misinformation": False}
        
        result = await generator.generate_output(
            "Hey there!",
            message_analysis,
            url_analysis,
            fact_results
        )
        
        assert "legitimate" in result.lower()

    @pytest.mark.asyncio
    async def test_error_handling(self, generator):
        result = await generator.generate_output(None, None, None, None)
        assert "legitimate" in result.lower()  # Safe default 