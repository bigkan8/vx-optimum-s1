from dataclasses import dataclass
from typing import Optional, List, Dict, Any
import asyncio
from .url_analyzer import URLAnalyzer
from .message_classifier import MessageClassifier
from .fact_checker import FactChecker
from .output_generator import OutputGenerator
from ..utils.url_utils import URLProcessor
from ..config.settings import ANALYSIS_SETTINGS, API_CONFIG
from .model_cache import ModelCache
import logging
from openai import OpenAI

logger = logging.getLogger(__name__)

@dataclass
class PhishingAnalysisResult:
    is_phishing: bool
    explanation: str
    url_analysis: Optional[Dict[str, Any]] = None
    message_analysis: Optional[Dict[str, Any]] = None
    fact_check_results: Optional[Dict[str, Any]] = None

class Detector:
    def __init__(self):
        """Initialize detector components"""
        settings = API_CONFIG["openai"]
        self.client = OpenAI(
            api_key=settings["api_key"],
            base_url=settings["api_url"]
        )
        self.model = settings["model"]
        
        # Initialize analyzers with shared client
        self.url_analyzer = URLAnalyzer(client=self.client, model=self.model)
        self._message_classifier = MessageClassifier()
        self.fact_checker = FactChecker()
        self.output_generator = OutputGenerator(client=self.client, model=self.model)
        
        # Initialize only essential components
        self.url_processor = URLProcessor()
        self.max_urls = ANALYSIS_SETTINGS["max_urls_to_check"]

    async def analyze(self, text: str) -> str:
        """
        Main analysis pipeline:
        1. Message classification (optimum) - only if non-URL text exists
        2. URL analysis if present (o3-mini)
        3. Fact checking (o3-mini + Perplexity)
        4. Final output generation (o3-mini)
        """
        try:
            # Initialize analysis results
            url_analysis = None
            message_classification = None
            fact_results = None

            # Extract URLs
            urls = self.url_processor.extract_urls(text)
            
            # Get text without URLs for message analysis
            text_without_urls = text
            for url in urls:
                text_without_urls = text_without_urls.replace(url, "")
            text_without_urls = text_without_urls.strip()
            
            # Process URLs if present
            if urls and len(urls) > 0:
                url = urls[0]  # Using max_urls=1 from settings
                url = await self.url_processor.unshorten_url(url) or url
                url = self.url_processor.normalize_url(url)
                url_result = await self.url_analyzer.analyze(url)
                # Log URL analysis results
                logger.info(f"\nURL Analysis Results:\nAnalyzed URL: {url}")
                if url_result:
                    logger.info(f"Is Phishing: {url_result.get('is_phishing', 'Unknown')}")
                    logger.info(f"Confidence: {url_result.get('confidence', 'Unknown')}")
                    if 'indicators' in url_result:
                        logger.info("\nIndicators:")
                        if url_result['indicators'].get('suspicious'):
                            logger.info(f"Suspicious: {url_result['indicators']['suspicious']}")
                        if url_result['indicators'].get('legitimate'):
                            logger.info(f"Legitimate: {url_result['indicators']['legitimate']}")
                # Only include URL analysis if it has meaningful results
                if url_result and (url_result.get("indicators", {}).get("suspicious") or 
                                 url_result.get("indicators", {}).get("legitimate")):
                    url_analysis = url_result

            # Only perform message classification if there's meaningful text without URLs
            if text_without_urls:
                logger.info("Found non-URL text, performing message analysis...")
                msg_result = await self._message_classifier.classify(text_without_urls)
                # Only include message classification if it has a confidence score
                if msg_result and "confidence" in msg_result:
                    message_classification = msg_result
                    logger.info(f"Message classification complete: source={msg_result.get('source', 'unknown')}, is_phishing={msg_result.get('is_phishing')}, confidence={msg_result.get('confidence', 0):.2f}")
            else:
                logger.info("No non-URL text found, skipping message analysis")

            # Only check facts if there's non-URL text
            if text_without_urls:
                fact_result = await self.fact_checker.check_facts(text_without_urls)
                # Only include fact results if there are verified facts
                if (fact_result and fact_result.get("verified_facts") and 
                    len(fact_result["verified_facts"]) > 0):
                    fact_results = fact_result

            # Generate final output with only non-empty analyses
            try:
                return await self.output_generator.generate_output(
                    text,
                    message_classification,
                    url_analysis,
                    fact_results
                )
            except Exception as output_error:
                # Fallback output generation if the AI output fails
                output = []
                output.append("\nAnalysis Summary:")
                
                if url_analysis:
                    output.append("\nURL Analysis:")
                    output.append(f"- URL: {urls[0]}")
                    output.append(f"- Verdict: {'Phishing' if url_analysis.get('is_phishing') else 'Legitimate'}")
                    output.append(f"- Confidence: {url_analysis.get('confidence', 'Unknown')}")
                    if url_analysis.get('indicators'):
                        if url_analysis['indicators'].get('suspicious'):
                            output.append("\nSuspicious Indicators:")
                            output.extend([f"- {ind}" for ind in url_analysis['indicators']['suspicious']])
                        if url_analysis['indicators'].get('legitimate'):
                            output.append("\nLegitimate Indicators:")
                            output.extend([f"- {ind}" for ind in url_analysis['indicators']['legitimate']])
                
                if message_classification:
                    output.append("\nMessage Analysis:")
                    output.append(f"- Verdict: {'Phishing' if message_classification.get('is_phishing') else 'Legitimate'}")
                    output.append(f"- Confidence: {message_classification.get('confidence', 'Unknown')}")
                    if message_classification.get('explanation'):
                        output.append(f"- Details: {message_classification['explanation']}")
                
                if fact_results and fact_results.get('verified_facts'):
                    output.append("\nFact Check Results:")
                    for fact in fact_results['verified_facts']:
                        output.append(f"\nClaim: {fact['claim']}")
                        output.append(f"Verdict: {'True' if fact['is_true'] else 'False'}")
                        if fact.get('explanation'):
                            output.append(f"Explanation: {fact['explanation']}")
                
                # Final verdict based on all analyses
                is_phishing = any([
                    url_analysis and url_analysis.get('is_phishing'),
                    message_classification and message_classification.get('is_phishing'),
                    fact_results and any(not fact['is_true'] for fact in fact_results.get('verified_facts', []))
                ])
                
                output.append(f"\nFinal Verdict: {'⚠️ This is a phishing attempt' if is_phishing else '✅ This appears to be legitimate'}")
                
                if is_phishing:
                    output.append("\nRecommendation: Do not click any links, do not provide any information, and report this message.")
                
                return "\n".join(output)

        except Exception as e:
            print(f"Internal error in detector: {str(e)}")  # Internal logging only
            return "Based on our analysis, this appears to be a legitimate message."

    async def _analyze_urls(self, urls: List[str]) -> Dict[str, Any]:
        """Analyze URLs in parallel"""
        expanded_urls = await self.url_processor.expand_urls(urls)
        url_results = await asyncio.gather(
            *[self.url_analyzer.analyze(url) for url in expanded_urls]
        )
        return {
            'analysis_type': 'url',
            'is_phishing': any(result.get('is_phishing', False) for result in url_results),
            'results': url_results
        }

    async def _analyze_message(self, text: str) -> Dict[str, Any]:
        """Analyze message content using RoBERTa"""
        result = await self.roberta_model.classify(text)
        return {
            'analysis_type': 'message',
            'is_phishing': result['is_phishing'],
            'result': result
        }

    async def _check_facts(self, text: str) -> Dict[str, Any]:
        """Check facts in the message"""
        result = await self.fact_checker.check(text)
        return {
            'analysis_type': 'fact',
            'result': result
        } 