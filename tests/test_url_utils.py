import pytest
from src.utils.url_utils import URLProcessor

@pytest.fixture
def url_processor():
    return URLProcessor()

@pytest.mark.asyncio
async def test_extract_urls():
    processor = URLProcessor()
    text = "Check this link: http://example.com and this: https://test.com"
    urls = await processor.extract_urls(text)
    assert len(urls) == 2
    assert "http://example.com" in urls 