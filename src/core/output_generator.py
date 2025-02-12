"""Output Generator Module

This module handles the generation of natural language analysis output for phishing detection results.
It includes both AI-powered generation and fallback mechanisms for robustness.

Recent Changes (2025-02-11):
1. Fixed NoneType errors in message handling:
   - Added safe dictionary initialization for all optional parameters in generate_output:
     message_analysis = message_analysis or {}
     url_analysis = url_analysis or {}
     fact_check_results = fact_check_results or {}
   - Added safe context creation in _make_api_call to prevent None values
   - Added type checking for dictionary operations
   - Fixed indicators access in message analysis results

2. Improved error handling:
   - Added try-except blocks in _make_api_call
   - Added proper logging for API call preparation errors
   - Enhanced fallback mechanism when API calls fail
   - Added better error context in log messages
   - Added retry mechanism with exponential backoff (3 attempts)
   - Added timeout handling with asyncio.wait_for

3. Enhanced safety checks:
   - Added isinstance checks for dictionary operations
   - Added safe default values for missing fields
   - Improved null safety in template formatting
   - Added validation for message analysis structure
   - Added safe dictionary access with .get() and default values
   - Added type checking before list operations

4. Message Analysis Fixes:
   - Fixed handling of RAG-enhanced analysis results
   - Added safe access to indicators field
   - Improved confidence score handling
   - Added source field validation
   - Added fallback for missing confidence scores (default 0.51)
   - Protected against missing or malformed indicators

5. Template Formatting Safety:
   - Added safe context creation before template formatting
   - Ensured all dictionary values have defaults
   - Protected against None values in string formatting
   - Added validation for required template fields
   - Added safe unpacking with **safe_context
   - Added proper error handling for format string errors

Known Issues:
- API errors are properly caught and handled with fallback
- Missing fields in message analysis are handled gracefully
- None values are converted to empty dictionaries to prevent errors
- Timeout errors trigger fallback to simpler output generation
- Some character formatting may be lost in fallback mode

"""

from typing import Dict, Any, Optional
import json
from openai import OpenAI
from ..config.prompts import FINAL_ANALYSIS_PROMPT
from ..config.settings import API_CONFIG
from ..utils.logger import Logger
import asyncio
import tenacity
from tenacity import retry, stop_after_attempt, wait_exponential

logger = Logger(__name__)

class OutputGenerator:
    def __init__(self, client: Optional[OpenAI] = None, model: Optional[str] = None):
        """Initialize output generator with optional client and model"""
        settings = API_CONFIG["openai"]
        self.client = client or OpenAI(
            api_key=settings["api_key"],
            base_url=settings["api_url"].rstrip("/"),  # Ensure no trailing slash
            timeout=settings["timeout"]
        )
        self.model = model or settings["model"]
        self.timeout = settings["timeout"]
        self.max_retries = 3

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
        """Generate final analysis output with natural expressions and comprehensive analysis"""
        try:
            # Log incoming data
            logger.debug(f"Message analysis received: {json.dumps(message_analysis, indent=2)}")
            
            # Ensure all values are dictionaries, not None
            message_analysis = message_analysis or {}
            url_analysis = url_analysis or {}
            fact_check_results = fact_check_results or {}
            
            # Prepare the context with all available information
            context = {
                "user_input": text,
                "message_classification": message_analysis,
                "url_analysis": url_analysis,
                "fact_results": fact_check_results
            }
            
            # Get the natural language analysis with timeout
            try:
                response = await asyncio.wait_for(
                    self._make_api_call(context),
                    timeout=self.timeout
                )
                
                result = response.choices[0].message.content
                logger.debug(f"Generated output: {result}")
                return result
                
            except asyncio.TimeoutError:
                logger.error("API request timed out, using fallback")
                return self._generate_natural_fallback(text, message_analysis, url_analysis, fact_check_results)
            except Exception as api_error:
                logger.error(f"API error in output generation: {str(api_error)}")
                return self._generate_natural_fallback(text, message_analysis, url_analysis, fact_check_results)
            
        except Exception as e:
            logger.error(f"Error in output generation: {str(e)}")
            return self._generate_natural_fallback(text, message_analysis, url_analysis, fact_check_results)

    async def _make_api_call(self, context: Dict[str, Any]):
        """Make the API call with retries"""
        try:
            # Ensure all context values are dictionaries, not None
            message_classification = context.get("message_classification") or {}
            url_analysis = context.get("url_analysis") or {}
            fact_results = context.get("fact_results") or {}
            
            # Prepare system message based on what analyses were performed
            system_message = """You are an expert phishing analyst who speaks in the style of one of these characters (pick one randomly for each analysis):

1. Jesse Pinkman (Breaking Bad):
- Uses "Yo" frequently
- Casual, street-smart language
- Ends sentences with "...bitch!"
- Expresses disbelief with "Yeah science!"
- Shows frustration with "This is bullshit, yo!"
- Uses phrases like "mad sus" and "straight up"

2. Harvey Specter (Suits):
- Confident, sharp, witty
- Uses legal analogies
- Says "That's the difference between you and me"
- Often starts with "Here's the thing"
- Uses "Now that's what I call..."
- Emphasizes winning and being the best

3. Elon Musk:
- Uses technical jargon mixed with memes
- Adds "haha" or "lmao" to serious statements
- Makes references to AI, rockets, or Mars
- Uses "Actually..." to correct things
- Adds "(obv)" or "!!" for emphasis
- Makes jokes about bots/algorithms

Analyze the following evidence and maintain your chosen character's style throughout."""

            # Add analysis sections based on available data
            if message_classification:
                system_message += "\n\nMessage Classification Available: Explain the model's verdict and confidence level."
                
            if url_analysis:
                system_message += "\n\nURL Analysis Available: Discuss the technical findings and indicators."
                
            if fact_results and fact_results.get("verified_facts"):
                system_message += "\n\nFact Verification Available: Review the verified claims and their sources."

            # Create a safe context for the prompt
            safe_context = {
                "user_input": context.get("user_input", ""),
                "message_classification": message_classification,
                "url_analysis": url_analysis,
                "fact_results": fact_results
            }

            return self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": system_message
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
            logger.error(f"Error in API call preparation: {str(e)}")
            raise

    def _generate_natural_fallback(
        self,
        text: str,
        message_analysis: Optional[Dict[str, Any]],
        url_analysis: Optional[Dict[str, Any]],
        fact_check_results: Optional[Dict[str, Any]]
    ) -> str:
        """Generate a natural, conversational analysis when AI generation fails"""
        # Start with a neutral opener
        output = "Let me analyze this carefully..."
        
        # Collect all evidence
        evidence = []
        
        # Add URL analysis if present
        if url_analysis and (url_analysis.get('indicators', {}).get('legitimate') or 
                           url_analysis.get('indicators', {}).get('suspicious')):
            output += "\n\nLooking at the URL analysis:"
            if url_analysis.get('indicators', {}).get('legitimate'):
                output += "\nLegitimate indicators:\n- " + "\n- ".join(url_analysis['indicators']['legitimate'][:3])
            if url_analysis.get('indicators', {}).get('suspicious'):
                output += "\nSuspicious indicators:\n- " + "\n- ".join(url_analysis['indicators']['suspicious'])
            evidence.append({
                "type": "url",
                "verdict": url_analysis.get('is_phishing'),
                "confidence": url_analysis.get('confidence', 0.51)
            })
        
        # Add message analysis if present
        if message_analysis and message_analysis.get('confidence', 0) > 0:
            output += "\n\nMessage analysis results:"
            source = message_analysis.get('source', '')
            
            if source == 'rag_enhanced':
                output += "\nEnhanced analysis with similar case matching:"
                if message_analysis.get('explanation'):
                    output += f"\n{message_analysis['explanation']}"
                
                # Safely handle indicators if they exist
                indicators = message_analysis.get('indicators', {})
                if isinstance(indicators, dict):  # Type check to ensure it's a dictionary
                    suspicious = indicators.get('suspicious', [])
                    legitimate = indicators.get('legitimate', [])
                    
                    if suspicious:
                        output += "\nSuspicious elements:\n- " + "\n- ".join(suspicious)
                    if legitimate:
                        output += "\nLegitimate elements:\n- " + "\n- ".join(legitimate)
            else:
                output += f"\nBase analysis confidence: {message_analysis.get('confidence', 0)*100:.1f}%"
            
            evidence.append({
                "type": "message",
                "verdict": message_analysis.get('is_phishing'),
                "confidence": message_analysis.get('confidence', 0.51),
                "source": source
            })
        
        # Add fact check results if present
        if fact_check_results and fact_check_results.get('verified_facts'):
            output += "\n\nFact verification results:"
            verified_true = 0
            verified_false = 0
            
            for fact in fact_check_results['verified_facts']:
                if fact['is_true']:
                    verified_true += 1
                    output += f"\n✓ {fact['claim']}"
                else:
                    verified_false += 1
                    output += f"\n✗ {fact['claim']}"
                    if fact.get('explanation'):
                        output += f"\n  Reason: {fact['explanation']}"
            
            evidence.append({
                "type": "facts",
                "true_count": verified_true,
                "false_count": verified_false
            })
        
        # Make a holistic determination
        output += "\n\nAnalyzing all evidence together:"
        
        # Consider verified facts first
        fact_evidence = next((e for e in evidence if e["type"] == "facts"), None)
        if fact_evidence:
            if fact_evidence["false_count"] > fact_evidence["true_count"]:
                output += "\n- Multiple verified facts proved false"
            elif fact_evidence["true_count"] > 0 and fact_evidence["false_count"] == 0:
                output += "\n- All verified facts checked out"
        
        # Consider RAG analysis if available
        rag_evidence = next((e for e in evidence if e["type"] == "message" and e["source"] == "rag_enhanced"), None)
        if rag_evidence:
            output += f"\n- Similar case analysis {'supports' if rag_evidence['verdict'] else 'contradicts'} phishing classification"
        
        # Consider URL technical analysis
        url_evidence = next((e for e in evidence if e["type"] == "url"), None)
        if url_evidence:
            output += f"\n- Technical URL analysis shows {'suspicious' if url_evidence['verdict'] else 'legitimate'} indicators"
        
        # Make final determination based on evidence weights
        is_phishing = False
        confidence = 0.51
        
        if fact_evidence and fact_evidence["false_count"] > fact_evidence["true_count"]:
            is_phishing = True
            confidence = 0.85
        elif rag_evidence and rag_evidence["confidence"] > 0.8:
            is_phishing = rag_evidence["verdict"]
            confidence = rag_evidence["confidence"]
        elif url_evidence and url_evidence["confidence"] > 0.8:
            is_phishing = url_evidence["verdict"]
            confidence = url_evidence["confidence"]
        else:
            # If no strong individual signals, look for consensus
            phishing_votes = sum(1 for e in evidence if e.get("verdict", False))
            total_votes = sum(1 for e in evidence if "verdict" in e)
            if total_votes > 0:
                is_phishing = phishing_votes > total_votes / 2
                confidence = 0.51 + (abs(phishing_votes - total_votes/2) / total_votes) * 0.3
        
        # Add conclusion
        output += f"\n\nBased on the totality of evidence (confidence: {confidence*100:.1f}%), "
        if is_phishing:
            output += "this appears to be a phishing attempt."
            output += "\n\nRecommendation: Do not interact with this message. Report it to your security team."
        else:
            output += "this appears to be legitimate."
            if confidence < 0.7:
                output += " However, always exercise caution with sensitive information."
        
        return output

    def _determine_final_verdict(
        self,
        url_analysis: Optional[Dict[str, Any]],
        message_analysis: Optional[Dict[str, Any]]
    ) -> bool:
        """
        Determine final phishing verdict based on URL and message analysis
        Considers both technical indicators and message patterns
        """
        # Initialize suspicion score
        suspicion_score = 0.0
        
        # Analyze message classification
        if message_analysis:
            if message_analysis.get("is_phishing"):
                # High confidence in message classification is a strong indicator
                if message_analysis.get("confidence", 0) > 0.8:
                    suspicion_score += 2.0
                else:
                    suspicion_score += 1.0
        
        # Analyze URL
        if url_analysis:
            # Even legitimate domains can be used in phishing
            if url_analysis.get("is_phishing", False):
                suspicion_score += 1.5
            # Being a verified domain reduces suspicion but doesn't eliminate it
            elif url_analysis.get("confidence") == 1.0:
                suspicion_score -= 0.5
        
        # Consider message patterns that indicate phishing
        suspicious_patterns = [
            "urgent", "immediate", "quickly", "asap",
            "password", "account", "verify", "confirm",
            "suspend", "disable", "cancel", "terminate"
        ]
        
        text_lower = str(message_analysis.get("text_analyzed", "")).lower()
        for pattern in suspicious_patterns:
            if pattern in text_lower:
                suspicion_score += 0.3  # Increment for each suspicious pattern
        
        # Return final verdict
        return suspicion_score >= 1.0  # Threshold for phishing determination

    def prepare_context(
        self,
        user_input: str,
        url_analysis: Optional[Dict[str, Any]] = None,
        message_analysis: Optional[Dict[str, Any]] = None,
        fact_check_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Prepare context for response generation"""
        return {
            "user_input": user_input,
            "url_analysis": url_analysis or {},
            "message_analysis": message_analysis or {},
            "fact_check_results": fact_check_results or {}
        }

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

        return max(confidences) if confidences else 0.51  # Default confidence 