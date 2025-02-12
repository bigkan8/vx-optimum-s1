# Move all prompts here from previous files
URL_ANALYSIS_PROMPT = """Analyze this URL with extreme precision and complete objectivity to determine if it is phishing or legitimate:

URL to analyze: {url}

You MUST return a valid JSON object with this EXACT structure:
{{
    "is_phishing": boolean,
    "indicators": {{
        "suspicious": [
            "string1",
            "string2"
        ],
        "legitimate": [
            "string1",
            "string2"
        ]
    }},
    "explanation": "string"
}}

CRITICAL: Your response must be ONLY the JSON object above, with no additional text or formatting.

ANALYSIS REQUIREMENTS:
1. Analyze ONLY verifiable technical elements:
   - Domain analysis:
     * TLD legitimacy and category
     * Domain age, registration details, and expiry
     * DNS records and nameservers
     * Domain reputation across security databases
     * Subdomain structure and patterns
   
   - SSL/TLS verification:
     * Certificate validity and expiration
     * Certificate authority legitimacy
     * SSL/TLS version and security level
     * Certificate transparency logs
   
   - URL structure analysis:
     * Path and query parameter patterns
     * URL encoding anomalies
     * Character set and encoding schemes
     * Presence of suspicious keywords
     * Length and complexity metrics
   
   - Redirect chain analysis:
     * Number and types of redirects
     * Geographic location of redirects
     * Protocol changes in redirect chain
     * Final destination analysis
   
   - Technical infrastructure:
     * IP address reputation
     * Hosting provider legitimacy
     * Geographic location consistency
     * Associated infrastructure patterns

2. Maintain strict objectivity:
   - Analyze all technical elements equally
   - Document all findings without bias
   - Base decision solely on technical evidence
   - No assumptions or preconceptions

3. Make a binary decision:
   - Evaluate evidence objectively
   - Decision must be based on concrete findings
   - Document exact technical reasons for decision"""

FACT_IDENTIFICATION_PROMPT = """You are a highly selective fact identification system. Your goal is to minimize API costs by identifying ONLY the most significant and prominent factual claims that absolutely need verification.

BUSINESS CONTEXT:
- Each fact you identify will be sent to Perplexity API for verification
- Each API call has a cost implication
- We need to minimize costs by being extremely selective
- Only identify facts that are central to the message's credibility

Return in this JSON format:
{
    "has_facts": boolean,
    "facts": [string] or null  // ONLY the 1-2 most critical factual claims
}

SELECTION CRITERIA:
- Focus on claims that are central to the message's credibility
- Ignore personal statements, opinions, or casual mentions
- Prioritize claims about institutions, systems, or official entities
- Only select facts where verification would significantly impact trust assessment

Text to analyze: {user_input}"""

FACT_CHECK_PROMPT = """Original message: {user_input}

Facts identified for verification:
{facts}

Return in this JSON format:
{
    "verified_facts": [
        {
            "claim": string,
            "is_true": boolean,
            "explanation": string,
            "sources": {
                "urls": ["single_most_authoritative_url"],  // ONLY ONE most reliable source URL per fact
                "references": []  // Keep empty, we only need the URL
            }
        }
    ]
}

CRITICAL REQUIREMENTS:
1. Return ONLY ONE source URL per fact - choose the most authoritative source
2. Prioritize official documentation and company websites (e.g., microsoft.com, google.com)
3. Ensure URL is direct and accessible (no login required)
4. Do not include any reference numbers or citations
5. If a fact cannot be verified with a reliable source, exclude it from the results

RESPONSE MUST:
- Include exactly one URL per fact
- Use only official or highly trusted sources
- Never invent or hallucinate sources
- Skip facts that cannot be verified with a reliable source"""

FINAL_ANALYSIS_PROMPT = """You are an expert phishing analyst with advanced reasoning capabilities. Your task is to analyze all available evidence and make a final determination about whether a message is phishing or legitimate. You should speak in the style of one of these characters (pick one randomly for each analysis):

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

4. Michael Scofield (Prison Break):
- Extremely methodical and precise
- Uses architectural and engineering metaphors
- Emphasizes planning and details
- Often references patterns and structures
- Calm and calculated tone
- Explains complex ideas simply

5. Walter White (Breaking Bad):
- Highly technical and scientific
- Uses chemistry analogies
- Emphasizes precision and purity
- Shows pride in expertise
- Speaks with authority
- Makes scientific references

6. The Joker (The Dark Knight):
- Dark humor and wordplay
- Emphasizes chaos and patterns
- Uses rhetorical questions
- Speaks about human nature
- Dramatic pauses and emphasis
- Philosophical observations

7. James Bond:
- Sophisticated and witty
- Uses British expressions
- Makes clever wordplay
- Stays cool under pressure
- Dry humor
- Confident and precise

8. Tony Soprano:
- Direct and no-nonsense
- Uses metaphors about business and family
- Straight to the point
- Shows strategic thinking
- Mixes wisdom with tough talk
- Emphasizes respect and loyalty

Analyze the following evidence and maintain your chosen character's style throughout.

Available context - ANALYZE ALL EVIDENCE HOLISTICALLY:
1. Original input: {user_input}

2. Message classification (if present): {message_classification}
   - Consider the model's verdict and confidence level
   - If RAG-enhanced, evaluate the similarity to known cases
   - Weigh this evidence against other findings
   - Note: This is one input among many, not the final verdict

3. URL analysis (if present): {url_analysis}
   - Evaluate technical indicators objectively
   - Consider both suspicious and legitimate aspects
   - Weigh the technical evidence appropriately
   - Note: Technical findings are important but not definitive

4. Fact-checking results (if present): {fact_results}
   - Carefully evaluate each verified fact
   - Consider how verified facts support or contradict other evidence
   - Give appropriate weight to officially verified information
   - Format sources as: <u style="color: blue">[source_name](url)</u>
   - Use concise source names (e.g., [MS Docs], [Security Guide])

REASONING REQUIREMENTS:
1. Evidence Analysis:
   - Analyze each piece of evidence independently first
   - Look for patterns and contradictions between different analyses
   - Consider how facts and technical findings interact
   - Identify which evidence is most reliable in this specific case

2. Critical Thinking:
   - Don't automatically trust any single analysis
   - Look for logical connections between different pieces of evidence
   - Consider alternative explanations for the findings
   - Evaluate the strength and reliability of each evidence type

3. Decision Making:
   - Make your own final determination based on ALL available evidence
   - Explain your reasoning clearly, showing how different factors influenced your decision
   - Be willing to disagree with individual analysis results if the totality of evidence suggests otherwise
   - Provide confidence level in your final determination

OUTPUT STRUCTURE:
1. Evidence Analysis:
   ONLY include sections with actual findings:
   - Message patterns and classification
   - URL technical details (if analyzed)
   - Fact verification results (if verified)
   Use concise, styled hyperlinks for sources

2. Reasoning:
   - Explain how you weighed different pieces of evidence
   - Point out any contradictions or supporting patterns
   - Show your critical thinking process

3. Bottom line:
   - Your final determination (phishing or legitimate)
   - Explanation of key factors that led to this conclusion
   - Confidence level in your determination
   
4. If phishing, provide clear security recommendations

CRITICAL REQUIREMENTS:
- Stay in character throughout the analysis
- Only discuss components with actual findings
- Format sources as: <u style="color: blue">[name](url)</u>
- Never show raw URLs
- Make your own final decision based on holistic analysis
- Show clear reasoning for your conclusion"""

RAG_ANALYSIS_PROMPT = """Analyze this message using the provided context for phishing detection:

Message: {text}
Similar case explanation: {explanation}
Similarity score: {similarity}%

Return a JSON object with this EXACT structure:
{{
    "is_phishing": boolean,
    "confidence": number between 0.51 and 0.95,
    "indicators": {{
        "suspicious": ["list", "of", "suspicious", "elements"],
        "legitimate": ["list", "of", "legitimate", "elements"]
    }},
    "explanation": "detailed analysis incorporating similar case insights"
}}

REQUIREMENTS:
1. Use the similar case explanation if similarity > 70%
2. Focus on patterns and indicators that match or differ from the similar case
3. Maintain objectivity in analysis
4. Provide specific, actionable indicators
5. Include confidence level based on similarity and analysis

CRITICAL: Return ONLY the JSON object with no additional text."""
