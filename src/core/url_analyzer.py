from typing import Dict, Any
import json
from openai import OpenAI
from ..config.prompts import URL_ANALYSIS_PROMPT
from ..config.settings import API_CONFIG, URL_SETTINGS
from ..utils.logger import Logger
import re
from urllib.parse import urlparse, unquote
import socket
import ssl
import whois
from datetime import datetime
import dns.resolver
import requests
import tldextract
import unicodedata
import asyncio

logger = Logger(__name__)

class URLAnalyzer:
    def __init__(self, client: OpenAI, model: str = "gpt-3.5-turbo-1106"):
        """Initialize URL analyzer with OpenAI client"""
        self.client = client
        self.model = model
        self.timeout = 30  # 30 second timeout for API calls
        self.user_agent = URL_SETTINGS["user_agent"]
        
        # Enhanced trusted domains with variations and TLDs
        self.trusted_domains = {
            'google': ['google.com', 'google.co.uk', 'google.ca', 'googleapis.com'],
            'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'azure.com'],
            'apple': ['apple.com', 'icloud.com'],
            'amazon': ['amazon.com', 'amazon.co.uk', 'aws.amazon.com'],
            'facebook': ['facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com'],
            'linkedin': ['linkedin.com', 'lnkd.in'],
            'github': ['github.com', 'githubusercontent.com'],
            'paypal': ['paypal.com', 'paypal.me'],
            'dropbox': ['dropbox.com', 'dropboxusercontent.com'],
            'adobe': ['adobe.com', 'typekit.com'],
            'twitter': ['twitter.com', 'x.com'],
            'netflix': ['netflix.com'],
            'spotify': ['spotify.com'],
            'bank': ['chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com']
        }
        
        # Common phishing keywords
        self.phishing_keywords = [
            'login', 'signin', 'verify', 'secure', 'account', 'security',
            'update', 'confirm', 'password', 'credential', 'authenticate',
            'wallet', 'recover', 'unlock', 'validate', 'kyc', 'support',
            'help', 'service', 'access', 'reset', 'billing', 'payment'
        ]
        
        # Suspicious TLDs often used in phishing
        self.suspicious_tlds = {
            '.xyz', '.top', '.work', '.date', '.racing', '.win', '.bid',
            '.stream', '.gq', '.ml', '.cf', '.ga', '.tk', '.pw'
        }

    def _get_ssl_info(self, domain: str) -> Dict[str, Any]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "valid": True,
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "expires": cert['notAfter'],
                        "version": ssock.version()
                    }
        except Exception as e:
            logger.error(f"SSL check failed for {domain}: {str(e)}")
            return {"valid": False, "error": str(e)}

    def _get_domain_info(self, domain: str) -> Dict[str, Any]:
        try:
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date,
                "last_updated": w.updated_date
            }
        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain}: {str(e)}")
            return {"error": str(e)}

    def _check_dns_records(self, domain: str) -> Dict[str, Any]:
        records = {}
        try:
            for record_type in ['A', 'MX', 'NS', 'TXT']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    records[record_type] = [str(rdata) for rdata in answers]
                except dns.resolver.NoAnswer:
                    records[record_type] = []
        except Exception as e:
            logger.error(f"DNS lookup failed for {domain}: {str(e)}")
            records["error"] = str(e)
        return records

    def _check_homograph_attack(self, domain: str) -> Dict[str, bool]:
        """Check for homograph attacks using similar-looking characters"""
        normalized = unicodedata.normalize('NFKC', domain)
        has_homograph = domain != normalized
        
        # Check for common character substitutions
        substitutions = {
            '1': 'l', 'l': '1', '0': 'o', 'o': '0',
            'rn': 'm', 'vv': 'w', 'cl': 'd', 'i': '1'
        }
        
        suspicious_chars = False
        for original, substitute in substitutions.items():
            if original in domain.lower() or substitute in domain.lower():
                suspicious_chars = True
                break
                
        return {
            "has_homograph": has_homograph,
            "has_suspicious_chars": suspicious_chars
        }

    def _analyze_url_structure(self, url: str, parsed: urlparse) -> Dict[str, Any]:
        """Detailed analysis of URL structure and patterns"""
        path = unquote(parsed.path).lower()
        query = unquote(parsed.query).lower()
        
        indicators = {
            "suspicious": [],
            "legitimate": []
        }
        
        # Check for suspicious URL patterns
        if any(kw in path or kw in query for kw in self.phishing_keywords):
            indicators["suspicious"].append("Contains common phishing keywords in URL")
            
        # Check for excessive subdomains
        subdomain_count = len(parsed.netloc.split('.')) - 2
        if subdomain_count > 3:
            indicators["suspicious"].append(f"Excessive subdomains ({subdomain_count})")
            
        # Check for URL encoding abuse
        if '%' in url:
            decoded = unquote(url)
            if '%' in decoded:  # Double encoding
                indicators["suspicious"].append("Contains double URL encoding")
                
        # Check for credential exposure in URL
        if '@' in parsed.netloc:
            indicators["suspicious"].append("Contains credentials in URL")
            
        # Check for IP address usage
        if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
            indicators["suspicious"].append("Uses IP address instead of domain name")
            
        # Check for port manipulation
        if parsed.port and parsed.port not in (80, 443):
            indicators["suspicious"].append(f"Uses non-standard port {parsed.port}")
            
        return indicators

    def _check_brand_impersonation(self, domain: str) -> Dict[str, Any]:
        """Check for brand impersonation attempts"""
        ext = tldextract.extract(domain)
        domain_parts = ext.domain.lower()
        
        indicators = {
            "suspicious": [],
            "legitimate": []
        }
        
        # Check for brand impersonation
        for brand, domains in self.trusted_domains.items():
            if brand in domain_parts and not any(domain.endswith(d) for d in domains):
                indicators["suspicious"].append(f"Potential {brand} impersonation")
                
            # Check for typosquatting
            for trusted_domain in domains:
                if self._levenshtein_distance(domain, trusted_domain) == 1:
                    indicators["suspicious"].append(f"Possible typosquatting of {trusted_domain}")
                    
        return indicators

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate the Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
            
        return previous_row[-1]

    def _basic_url_check(self, url: str) -> Dict[str, Any]:
        """Enhanced comprehensive technical URL analysis"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        ext = tldextract.extract(domain)
        
        indicators = {
            "suspicious": [],
            "legitimate": []
        }
        
        # Check for trusted domains
        for brand, trusted_domains in self.trusted_domains.items():
            if any(domain.endswith(td) for td in trusted_domains):
                return {
                    "is_phishing": False,
                    "confidence": 1.0,
                    "indicators": {
                        "suspicious": [],
                        "legitimate": [f"Verified {brand} domain"]
                    },
                    "explanation": f"This is a verified {brand} domain and is therefore legitimate."
                }
        
        # Check TLD
        if ext.suffix in self.suspicious_tlds:
            indicators["suspicious"].append(f"Uses suspicious TLD: {ext.suffix}")
        
        # Protocol analysis
        if parsed.scheme == "https":
            indicators["legitimate"].append("Uses secure HTTPS protocol")
            ssl_info = self._get_ssl_info(domain)
            if ssl_info["valid"]:
                indicators["legitimate"].extend([
                    f"Valid SSL certificate from {ssl_info['issuer'].get('organizationName', 'Unknown CA')}",
                    f"Certificate expires: {ssl_info['expires']}"
                ])
            else:
                indicators["suspicious"].append("Invalid or missing SSL certificate")
        else:
            indicators["suspicious"].append("Uses insecure HTTP protocol")

        # Domain age and registration
        domain_info = self._get_domain_info(domain)
        if isinstance(domain_info, dict) and not domain_info.get("error"):
            creation_date = domain_info.get("creation_date")
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if isinstance(creation_date, datetime):
                    age = (datetime.now() - creation_date).days
                    if age > 365:
                        indicators["legitimate"].append(f"Domain is well established ({age} days old)")
                    elif age < 30:
                        indicators["suspicious"].append(f"Very recently registered domain ({age} days old)")
                    else:
                        indicators["suspicious"].append(f"Recently registered domain ({age} days old)")

        # DNS analysis
        dns_records = self._check_dns_records(domain)
        if not dns_records.get("error"):
            if dns_records.get("MX") and dns_records.get("NS"):
                indicators["legitimate"].append("Complete DNS records present")
            else:
                indicators["suspicious"].append("Incomplete DNS records")

        # Check for homograph attacks
        homograph_check = self._check_homograph_attack(domain)
        if homograph_check["has_homograph"]:
            indicators["suspicious"].append("Possible homograph attack detected")
        if homograph_check["has_suspicious_chars"]:
            indicators["suspicious"].append("Contains suspicious character substitutions")

        # URL structure analysis
        structure_indicators = self._analyze_url_structure(url, parsed)
        indicators["suspicious"].extend(structure_indicators["suspicious"])
        indicators["legitimate"].extend(structure_indicators["legitimate"])

        # Brand impersonation check
        brand_indicators = self._check_brand_impersonation(domain)
        indicators["suspicious"].extend(brand_indicators["suspicious"])
        indicators["legitimate"].extend(brand_indicators["legitimate"])

        # Generate explanation
        explanation = "Technical analysis reveals:\n"
        if indicators["legitimate"]:
            explanation += "\nLegitimate indicators:\n- " + "\n- ".join(indicators["legitimate"])
        if indicators["suspicious"]:
            explanation += "\nSuspicious indicators:\n- " + "\n- ".join(indicators["suspicious"])

        # Enhanced confidence calculation
        legitimate_count = len(indicators["legitimate"])
        suspicious_count = len(indicators["suspicious"])
        total_count = legitimate_count + suspicious_count
        
        # Base confidence
        if total_count == 0:
            confidence = 0.51
        else:
            # Weight suspicious indicators more heavily
            weighted_suspicious = suspicious_count * 1.5
            weighted_total = weighted_suspicious + legitimate_count
            confidence = weighted_suspicious / weighted_total
            
            # Adjust based on critical indicators
            critical_indicators = [
                "Possible homograph attack detected",
                "Contains credentials in URL",
                "Uses IP address instead of domain name",
                "Contains double URL encoding",
                "Very recently registered domain"
            ]
            
            if any(ind in indicators["suspicious"] for ind in critical_indicators):
                confidence = min(0.95, confidence + 0.2)
            
            # Floor and ceiling
            confidence = max(0.05, min(0.95, confidence))

        return {
            "is_phishing": confidence > 0.5,
            "confidence": confidence,
            "indicators": indicators,
            "explanation": explanation
        }

    async def analyze(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL using both technical checks and AI model
        Returns analysis with phishing indicators
        """
        try:
            # First do comprehensive technical checks
            basic_result = self._basic_url_check(url)
            
            # If it's a known trusted domain, return immediately
            if basic_result.get("confidence") == 1.0:
                return basic_result
            
            # Get AI analysis with timeout protection
            try:
                # Create completion with async client
                response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a URL security analyzer. Analyze URLs for phishing indicators."
                    },
                    {
                        "role": "user",
                        "content": URL_ANALYSIS_PROMPT.format(url=url)
                    }
                ],
                    response_format={ "type": "json_object" }  # Ensure JSON response
                )
                
                content = response.choices[0].message.content.strip()
                
                # Validate response format
                if not content.startswith('{') or not content.endswith('}'):
                    logger.error(f"Invalid JSON format in response: {content}")
                    return basic_result
                    
                try:
                    # Try direct JSON parsing first
                    ai_result = json.loads(content)
                    
                    # Validate required fields
                    if not isinstance(ai_result, dict):
                        logger.error("Response is not a dictionary")
                        return basic_result
                        
                    required_fields = ["is_phishing", "indicators", "explanation"]
                    missing_fields = [field for field in required_fields if field not in ai_result]
                    if missing_fields:
                        logger.error(f"Missing required fields: {missing_fields}")
                        return basic_result
                        
                    if not isinstance(ai_result["indicators"], dict):
                        logger.error("Indicators field is not a dictionary")
                        return basic_result
                        
                    required_indicators = ["suspicious", "legitimate"]
                    missing_indicators = [ind for ind in required_indicators if ind not in ai_result["indicators"]]
                    if missing_indicators:
                        logger.error(f"Missing required indicators: {missing_indicators}")
                        return basic_result
                        
                except json.JSONDecodeError as e:
                    logger.error(f"JSON parse error: {str(e)}\nContent: {content}")
                    return basic_result
                
            except (asyncio.TimeoutError, KeyboardInterrupt) as e:
                logger.warning(f"API call interrupted or timed out: {str(e)}")
                return basic_result
            except Exception as e:
                logger.error(f"Error in AI URL analysis: {str(e)}")
                return basic_result

            # Combine results, giving precedence to technical analysis but incorporating AI insights
            combined_indicators = {
                "suspicious": list(set(basic_result["indicators"]["suspicious"] + 
                                    ai_result.get("indicators", {}).get("suspicious", []))),
                "legitimate": list(set(basic_result["indicators"]["legitimate"] + 
                                    ai_result.get("indicators", {}).get("legitimate", [])))
            }
            
            # Combine explanations
            combined_explanation = basic_result["explanation"]
            if ai_result.get("explanation"):
                combined_explanation += "\n\nAI Analysis:\n" + ai_result["explanation"]

            return {
                "is_phishing": len(combined_indicators["suspicious"]) > len(combined_indicators["legitimate"]),
                "confidence": basic_result["confidence"],  # Keep the technical confidence
                "indicators": combined_indicators,
                "explanation": combined_explanation
            }

        except Exception as e:
            logger.error(f"Critical error in URL analysis: {str(e)}")
            # Return conservative default with explanation
            return {
                "is_phishing": False,
                "confidence": 0.51,
                "indicators": {
                    "suspicious": ["Analysis failed - proceed with caution"],
                    "legitimate": []
                },
                "explanation": f"URL analysis failed: {str(e)}. Proceed with caution."
            } 