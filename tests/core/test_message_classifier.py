import pytest
from src.core.message_classifier import MessageClassifier

@pytest.fixture
def classifier():
    return MessageClassifier()

class TestMessageClassifier:
    @pytest.mark.asyncio
    async def test_classify_phishing_message(self, classifier):
        text = "URGENT: Your account has been suspended. Click here to verify: http://suspicious-site.com"
        result = await classifier.classify(text)
        
        assert result["is_phishing"] == True
        assert result["confidence"] > 0.5
        assert result["model_name"] == "finetuned_dapt_roberta"
        assert "text_analyzed" in result

    @pytest.mark.asyncio
    async def test_classify_legitimate_message(self, classifier):
        text = "Hey, how are you? Let's meet for coffee tomorrow at 2pm."
        result = await classifier.classify(text)
        
        assert result["is_phishing"] == False
        assert result["confidence"] > 0.5
        assert "text_analyzed" in result

    @pytest.mark.asyncio
    async def test_classify_empty_message(self, classifier):
        result = await classifier.classify("")
        
        assert result["is_phishing"] == False  # Safe default
        assert "error" in result

    @pytest.mark.asyncio
    async def test_classify_long_message(self, classifier):
        # Test with message longer than max_length
        text = "test " * 1000
        result = await classifier.classify(text)
        
        assert len(result["text_analyzed"]) < len(text)
        assert "..." in result["text_analyzed"]

    @pytest.mark.asyncio
    async def test_model_confidence(self, classifier):
        # Test confidence scores are reasonable
        text = "Click here to claim your prize!!!"
        result = await classifier.classify(text)
        
        assert 0 <= result["confidence"] <= 1.0

    @pytest.mark.asyncio
    async def test_error_handling(self, classifier):
        # Test with malformed input
        text = None
        result = await classifier.classify(text)
        
        assert "error" in result
        assert result["is_phishing"] == False  # Safe default 

    def test_model_initialization():
        classifier = MessageClassifier()
        result = classifier.get_model_info()
        assert result["model_name"] == "optimum" 