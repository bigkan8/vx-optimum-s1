import re
import httpx
from typing import Optional, List
from urllib.parse import urlparse, urljoin
from ..config.settings import Settings, URL_SETTINGS
from .logger import Logger

logger = Logger(__name__)

class URLProcessor:
    """
    Handles URL processing operations:
    - URL extraction with comprehensive pattern matching
    - URL unshortening with proper redirect handling
    - URL normalization with scheme and path handling
    - URL removal for clean text analysis
    """
    
    # Comprehensive URL pattern as class variable since it's constant
    URL_PATTERN = re.compile(
        r'(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:\'".,<>?«»""''])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@)))'
    )

    def __init__(self):
        self.max_redirects = URL_SETTINGS["max_redirects"]
        self.timeout = URL_SETTINGS["timeout"]
        self.user_agent = URL_SETTINGS["user_agent"]

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract URLs from text using comprehensive pattern matching"""
        return re.findall(URLProcessor.URL_PATTERN, text)

    @staticmethod
    async def unshorten_url(url: str) -> Optional[str]:
        """Unshorten URLs by following redirects"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    follow_redirects=True,
                    timeout=Settings.URL_TIMEOUT
                )
                return str(response.url)
        except Exception as e:
            logger.error(f"Failed to unshorten URL: {str(e)}")
            return None

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL by adding scheme if missing and handling relative paths"""
        if not url:
            return url
        
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        try:
            parsed = urlparse(url)
            # Normalize the path
            path = parsed.path or '/'
            # Rebuild URL with normalized components and preserve query parameters
            return urljoin(
                f"{parsed.scheme}://{parsed.netloc}",
                path + ('?' + parsed.query if parsed.query else '')
            )
        except Exception as e:
            logger.error(f"Failed to normalize URL: {str(e)}")
            return url

    def remove_urls(self, text: str) -> str:
        """Remove URLs from text to get clean message content"""
        return re.sub(self.URL_PATTERN, '', text).strip()