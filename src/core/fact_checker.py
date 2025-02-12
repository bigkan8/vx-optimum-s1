from typing import Dict, Any, List
import json
from openai import OpenAI
from ..config.prompts import FACT_IDENTIFICATION_PROMPT, FACT_CHECK_PROMPT
from ..config.settings import API_CONFIG, ANALYSIS_SETTINGS
from ..utils.logger import Logger

logger = Logger(__name__)

class FactChecker:
    def __init__(self):
        openai_settings = API_CONFIG["openai"]
        perplexity_settings = API_CONFIG["perplexity"]
        
        # O3 client for fact identification
        self.o3_client = OpenAI(
            api_key=openai_settings["api_key"],
            base_url=openai_settings["api_url"]
        )
        self.o3_model = openai_settings["model"]
        
        # Perplexity client for fact verification
        self.perplexity_client = OpenAI(
            api_key=perplexity_settings["api_key"],
            base_url=perplexity_settings["api_url"]
        )
        self.perplexity_model = perplexity_settings["model"]
        self.perplexity_timeout = perplexity_settings["timeout"]
        
        self.max_facts = ANALYSIS_SETTINGS["max_facts_to_check"]

    async def check_facts(self, text: str) -> Dict[str, Any]:
        """
        Two-step fact checking process:
        1. Use o3-mini to identify factual claims
        2. Use Perplexity's sonar-reasoning-pro to verify those claims
        """
        try:
            # Step 1: Identify facts using o3-mini
            identified_facts = await self._identify_facts(text)
            logger.info(f"Identified facts: {identified_facts}")
            
            if not identified_facts.get('has_facts'):
                return {
                    "verified_facts": []
                }

            # Step 2: Verify identified facts using Perplexity
            verification_results = await self._verify_facts_with_perplexity(
                user_input=text,
                facts=identified_facts.get('facts', [])
            )
            logger.info(f"Verification results: {verification_results}")  # Log verification results
            
            return verification_results

        except Exception as e:
            logger.error(f"Error in fact checking: {str(e)}")
            return {
                "verified_facts": [],
                "error": str(e)
            }

    async def _identify_facts(self, text: str) -> Dict[str, Any]:
        """Use o3-mini to identify factual claims in the text"""
        try:
            response = self.o3_client.chat.completions.create(
                model=self.o3_model,
                messages=[
                    {
                        "role": "system",
                        "content": FACT_IDENTIFICATION_PROMPT
                    },
                    {
                        "role": "user",
                        "content": f"Extract verifiable factual claims from this text: {text}"
                    }
                ],
                response_format={ "type": "json_object" }  # Request JSON response
            )
            
            content = response.choices[0].message.content.strip()
            
            # Handle potential JSON formatting issues
            try:
                # Try direct JSON parsing first
                result = json.loads(content)
            except json.JSONDecodeError as e:
                logger.error(f"JSON parse error: {str(e)}\nContent: {content}")
                # Try to extract JSON from the response if it's wrapped in text
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    try:
                        result = json.loads(content[json_start:json_end])
                    except json.JSONDecodeError:
                        logger.error(f"Failed to extract valid JSON from response: {content}")
                        return {"has_facts": False, "facts": []}
                else:
                    logger.error(f"No JSON object found in response: {content}")
                    return {"has_facts": False, "facts": []}
            
            # Validate and clean the response
            if not isinstance(result, dict):
                logger.error(f"Response is not a dictionary: {result}")
                return {"has_facts": False, "facts": []}
            
            # Ensure required fields exist with correct types
            cleaned_result = {
                "has_facts": False,
                "facts": []
            }
            
            if "facts" in result and isinstance(result["facts"], list):
                # Clean and validate each fact
                cleaned_facts = []
                for fact in result["facts"]:
                    if isinstance(fact, (str, int, float)):
                        cleaned_fact = str(fact).strip()
                        if cleaned_fact:  # Only include non-empty facts
                            cleaned_facts.append(cleaned_fact)
                
                cleaned_result["facts"] = cleaned_facts
                cleaned_result["has_facts"] = bool(cleaned_facts)  # True if we have any valid facts
            
            return cleaned_result

        except Exception as e:
            logger.error(f"Error in fact identification: {str(e)}")
            return {"has_facts": False, "facts": []}

    async def _verify_facts_with_perplexity(self, user_input: str, facts: List[str]) -> Dict[str, Any]:
        """Use Perplexity's sonar-reasoning-pro to verify identified facts"""
        try:
            # Limit the number of facts to check
            facts_to_check = facts[:self.max_facts]
            
            # Create the chat completion request with modified system prompt for single source
            response = self.perplexity_client.chat.completions.create(
                model=self.perplexity_model,
                messages=[
                    {
                        "role": "system",
                        "content": """You are a fact verification assistant. Verify claims and respond with ONLY a JSON object in this format:
{
    "verified_facts": [
        {
            "claim": "exact claim",
            "is_true": boolean,
            "explanation": "verification details",
            "sources": {
                "urls": ["single_most_authoritative_url"],  // Only ONE most reliable source URL
                "references": []  // Keep empty, we only need the URL
            }
        }
    ]
}

CRITICAL REQUIREMENTS:
1. Return ONLY ONE source URL per fact - choose the most authoritative source
2. Prioritize official documentation, company websites, or trusted security resources
3. Do not include reference numbers, only the URL
4. Ensure URL is direct and accessible (no login required)
5. Verify ALL facts in a single API call"""
                    },
                    {
                        "role": "user",
                        "content": f"Verify these claims and respond with ONLY JSON:\n{json.dumps(facts_to_check)}"
                    }
                ]
            )
            
            content = response.choices[0].message.content.strip()
            
            # Try to extract JSON from the response
            try:
                # First try direct parsing
                result = json.loads(content)
            except json.JSONDecodeError:
                # If that fails, try to extract JSON portion
                try:
                    # Find the first { and last }
                    json_start = content.find('{')
                    json_end = content.rfind('}') + 1
                    if json_start >= 0 and json_end > json_start:
                        json_str = content[json_start:json_end]
                        # Clean up any potential markdown code block markers
                        json_str = json_str.replace('```json', '').replace('```', '')
                        result = json.loads(json_str.strip())
                    else:
                        raise ValueError("No JSON object found in response")
                except Exception as e:
                    logger.error(f"Failed to extract JSON: {str(e)}\nContent: {content}")
                    return {
                        "verified_facts": [],
                        "error": "Failed to parse response"
                    }
            
            # Validate structure
            if not isinstance(result, dict) or "verified_facts" not in result:
                logger.error(f"Invalid structure: {result}")
                return {
                    "verified_facts": [],
                    "error": "Invalid response structure"
                }
            
            # Clean and validate facts - ensure single source URL
            cleaned_facts = []
            for fact in result.get("verified_facts", []):
                if isinstance(fact, dict) and all(k in fact for k in ["claim", "is_true", "explanation", "sources"]):
                    # Ensure only one URL per fact
                    if isinstance(fact["sources"], dict):
                        urls = fact["sources"].get("urls", [])
                        if urls and len(urls) > 0:
                            fact["sources"]["urls"] = [urls[0]]  # Keep only the first URL
                            fact["sources"]["references"] = []  # Clear references
                            cleaned_facts.append(fact)
            
            return {"verified_facts": cleaned_facts}

        except Exception as e:
            logger.error(f"Error in fact verification: {str(e)}")
            return {
                "verified_facts": [],
                "error": f"Error in fact verification: {str(e)}"
            } 