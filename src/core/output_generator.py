"""Output Generator Module

This module handles the generation of natural language analysis output for phishing detection results.
It focuses on key technical details while maintaining a natural conversational style."""

from typing import Dict, Any, Optional
import json
from openai import OpenAI
from ..config.prompts import FINAL_ANALYSIS_PROMPT
from ..config.settings import API_CONFIG
from ..utils.character_selector import CharacterSelector
import asyncio
import tenacity
from tenacity import retry, stop_after_attempt, wait_exponential

class OutputGenerator:
    def __init__(self, client: Optional[OpenAI] = None, model: Optional[str] = None):
        """Initialize output generator with optional client and model"""
        settings = API_CONFIG["openai"]
        self.client = client or OpenAI(
            api_key=settings["api_key"],
            base_url=settings["api_url"].rstrip("/"),
            timeout=settings["timeout"]
        )
        self.model = model or settings["model"]
        self.timeout = settings["timeout"]
        self.max_retries = 3
        self.character_selector = CharacterSelector()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=tenacity.retry_if_exception_type((Exception))
    )
    async def generate_output(
        self,
        text: str,
        message_analysis: Optional[Dict[str, Any]] = None,
        url_analysis: Optional[Dict[str, Any]] = None,
        fact_check_results: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate final analysis output with natural expressions and key technical details"""
        try:
            # Ensure all values are dictionaries, not None
            message_analysis = message_analysis or {}
            url_analysis = url_analysis or {}
            fact_check_results = fact_check_results or {}
            
            # Select random character for analysis style
            character = self.character_selector.get_random_character()
            
            # Create completion with async client
            try:
                response = await asyncio.wait_for(
                    self._make_api_call(text, message_analysis, url_analysis, fact_check_results, character),
                    timeout=self.timeout
                )
                
                return response.choices[0].message.content
                
            except asyncio.TimeoutError:
                return self._generate_natural_fallback(text, message_analysis, url_analysis, fact_check_results)
            except Exception as api_error:
                return self._generate_natural_fallback(text, message_analysis, url_analysis, fact_check_results)
            
        except Exception as e:
            return self._generate_natural_fallback(text, message_analysis, url_analysis, fact_check_results)

    async def _make_api_call(
        self, 
        text: str,
        message_analysis: Dict[str, Any],
        url_analysis: Dict[str, Any],
        fact_check_results: Dict[str, Any],
        character: Dict[str, Any]
    ):
        """Make the API call with retries"""
        try:
            # Create a safe context for the prompt
            safe_context = {
                "user_input": text,
                "message_classification": message_analysis,
                "url_analysis": url_analysis,
                "fact_results": fact_check_results,
                "character": self.character_selector.get_character_prompt(character)
            }

            return self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": f"You are an expert phishing analyst. {safe_context['character']}"
                    },
                    {
                        "role": "user",
                        "content": FINAL_ANALYSIS_PROMPT.format(**safe_context)
                    }
                ],
                response_format={"type": "text"},
                timeout=self.timeout
            )
        except Exception as e:
            raise

    def _generate_natural_fallback(
        self,
        text: str,
        message_analysis: Optional[Dict[str, Any]],
        url_analysis: Optional[Dict[str, Any]],
        fact_check_results: Optional[Dict[str, Any]]
    ) -> str:
        """Generate a natural, focused analysis when AI generation fails"""
        output = []
        
        # Add URL analysis if present
        if url_analysis and (url_analysis.get('indicators', {}).get('legitimate') or 
                           url_analysis.get('indicators', {}).get('suspicious')):
            output.append("\nURL Analysis:")
            if url_analysis.get('indicators', {}).get('suspicious'):
                output.append("Suspicious indicators:\n- " + "\n- ".join(url_analysis['indicators']['suspicious'][:3]))
            if url_analysis.get('indicators', {}).get('legitimate'):
                output.append("Legitimate indicators:\n- " + "\n- ".join(url_analysis['indicators']['legitimate'][:3]))
        
        # Add message analysis if present
        if message_analysis and message_analysis.get('confidence', 0) > 0:
            output.append("\nMessage Analysis:")
            if message_analysis.get('explanation'):
                output.append(message_analysis['explanation'])
            
            # Safely handle indicators
            indicators = message_analysis.get('indicators', {})
            if isinstance(indicators, dict):
                suspicious = indicators.get('suspicious', [])
                legitimate = indicators.get('legitimate', [])
                
                if suspicious:
                    output.append("Suspicious elements:\n- " + "\n- ".join(suspicious))
                if legitimate:
                    output.append("Legitimate elements:\n- " + "\n- ".join(legitimate))
        
        # Add fact check results if present
        if fact_check_results and fact_check_results.get('verified_facts'):
            output.append("\nFact Verification:")
            for fact in fact_check_results['verified_facts']:
                status = "✓" if fact['is_true'] else "✗"
                output.append(f"\n{status} {fact['claim']}")
                if not fact['is_true'] and fact.get('explanation'):
                    output.append(f"  Reason: {fact['explanation']}")
                if fact.get('sources', {}).get('urls'):
                    url = fact['sources']['urls'][0]
                    output.append(f"  Source: <u style='color: blue'>[Verification]({url})</u>")
        
        # Make final determination
        is_phishing = self._determine_final_verdict(url_analysis, message_analysis)
        confidence = self._calculate_confidence(url_analysis, message_analysis)
        
        output.append(f"\nVerdict ({confidence*100:.1f}% confidence):")
        if is_phishing:
            output.append("This is a phishing attempt.")
            output.append("\nRecommendation: Do not interact with this message. Report it to your security team.")
        else:
            output.append("This appears to be legitimate.")
            if confidence < 0.7:
                output.append("However, always exercise caution with sensitive information.")
        
        return "\n".join(output)

    def _determine_final_verdict(
        self,
        url_analysis: Optional[Dict[str, Any]],
        message_analysis: Optional[Dict[str, Any]]
    ) -> bool:
        """Determine final phishing verdict based on evidence"""
        suspicion_score = 0.0
        
        if message_analysis and message_analysis.get("is_phishing"):
            if message_analysis.get("confidence", 0) > 0.8:
                suspicion_score += 2.0
            else:
                suspicion_score += 1.0
        
        if url_analysis:
            if url_analysis.get("is_phishing", False):
                suspicion_score += 1.5
            elif url_analysis.get("confidence") == 1.0:
                suspicion_score -= 0.5
        
        return suspicion_score >= 1.0

    def _calculate_confidence(
        self,
        url_analysis: Optional[Dict[str, Any]],
        message_analysis: Optional[Dict[str, Any]]
    ) -> float:
        """Calculate overall confidence score"""
        confidences = []
        
        if url_analysis and 'confidence' in url_analysis:
            confidences.append(url_analysis['confidence'])
        
        if message_analysis and 'confidence' in message_analysis:
            confidences.append(message_analysis['confidence'])

        return max(confidences) if confidences else 0.51 