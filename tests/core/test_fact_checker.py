import pytest
from src.core.fact_checker import FactChecker

@pytest.fixture
def fact_checker():
    return FactChecker()

class TestFactChecker:
    @pytest.mark.asyncio
    async def test_check_facts_with_claims(self, fact_checker):
        text = "The Earth is flat and was created in 1920."
        result = await fact_checker.check_facts(text)
        
        assert "facts" in result
        assert len(result["facts"]) > 0
        assert "verification" in result
        assert result["contains_misinformation"] == True

    @pytest.mark.asyncio
    async def test_check_facts_legitimate(self, fact_checker):
        text = "The Earth orbits around the Sun."
        result = await fact_checker.check_facts(text)
        
        assert "facts" in result
        assert result["contains_misinformation"] == False

    @pytest.mark.asyncio
    async def test_check_facts_no_claims(self, fact_checker):
        text = "Hey, how are you doing?"
        result = await fact_checker.check_facts(text)
        
        assert len(result["facts"]) == 0
        assert result["contains_misinformation"] == False

    @pytest.mark.asyncio
    async def test_error_handling(self, fact_checker):
        result = await fact_checker.check_facts(None)
        assert "error" in result 