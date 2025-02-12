import pytest
from src.utils.url_utils import URLProcessor

@pytest.fixture
def url_processor():
    return URLProcessor()

class TestURLProcessor:
    def test_extract_urls(self, url_processor):
        # Test various URL formats
        text = """
        Check out https://example.com and http://test.org/path?q=123
        Also visit subdomain.example.co.uk/test
        And shortened bit.ly/abc123
        """
        urls = url_processor.extract_urls(text)
        assert len(urls) == 4
        assert "https://example.com" in urls
        assert "http://test.org/path?q=123" in urls
        assert "subdomain.example.co.uk/test" in urls
        assert "bit.ly/abc123" in urls

    @pytest.mark.asyncio
    async def test_unshorten_url(self, url_processor):
        # Test URL unshortening
        short_url = "https://bit.ly/example"
        long_url = await url_processor.unshorten_url(short_url)
        assert long_url is not None
        assert long_url.startswith("http")

    def test_normalize_url(self, url_processor):
        test_cases = [
            # [input, expected]
            ["example.com", "https://example.com/"],
            ["http://example.com", "http://example.com/"],
            ["https://example.com/path", "https://example.com/path"],
            ["https://example.com/path?q=123", "https://example.com/path?q=123"],
            ["example.com:80", "https://example.com/"],
            ["example.com/path/../other", "https://example.com/other"],
        ]
        
        for input_url, expected in test_cases:
            assert url_processor.normalize_url(input_url) == expected

    def test_remove_urls(self, url_processor):
        text = "Check out https://example.com and visit http://test.org"
        clean_text = url_processor.remove_urls(text)
        assert clean_text == "Check out and visit"
        assert "example.com" not in clean_text
        assert "test.org" not in clean_text

    def test_extract_urls_no_urls(self, url_processor):
        text = "This text contains no URLs"
        urls = url_processor.extract_urls(text)
        assert len(urls) == 0

    def test_normalize_url_empty(self, url_processor):
        assert url_processor.normalize_url("") == ""

    @pytest.mark.asyncio
    async def test_unshorten_url_invalid(self, url_processor):
        result = await url_processor.unshorten_url("https://invalid.url.that.doesnt.exist")
        assert result is None 