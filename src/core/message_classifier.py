from typing import Dict, Any, List
import torch
from transformers import RobertaForSequenceClassification, RobertaTokenizer
import numpy as np
from ..config.settings import MODEL_SETTINGS, API_CONFIG
from ..utils.logger import Logger
import re
import json
from openai import OpenAI
from pydantic import BaseModel, Field
from pinecone import Pinecone
import logging
from ..config.prompts import RAG_ANALYSIS_PROMPT

logger = Logger(__name__)

class Indicators(BaseModel):
    suspicious: List[str] = Field(description="List of suspicious elements found")
    legitimate: List[str] = Field(description="List of legitimate elements found")

class MessageAnalysis(BaseModel):
    is_phishing: bool = Field(description="Whether the message appears to be a phishing attempt")
    confidence: float = Field(description="Confidence score between 0 and 1", ge=0, le=1)
    indicators: Indicators = Field(description="Indicators of phishing or legitimacy")
    explanation: str = Field(description="Detailed analysis explanation")

class MessageClassifier:
    def __init__(self):
        try:
            settings = MODEL_SETTINGS["message_classifier"]
            self.model_name = settings["name"]
            self.model_path = settings["path"]
            self.max_length = settings["max_length"]
            
            # Confidence thresholds
            self.high_confidence_threshold = 0.85
            self.max_confidence_cap = 0.95
            self.min_confidence_threshold = 0.60
            
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            logger.info(f"Using device: {self.device}")
            
            self.tokenizer = RobertaTokenizer.from_pretrained(self.model_path)
            self.model = RobertaForSequenceClassification.from_pretrained(self.model_path)
            self.model.to(self.device)
            self.model.eval()
            
            # Initialize OpenAI client
            openai_settings = API_CONFIG["openai"]
            self.client = OpenAI(
                api_key=openai_settings["api_key"],
                base_url=openai_settings["api_url"],
                timeout=openai_settings["timeout"]
            )
            
            # Initialize Pinecone for RAG
            self.pinecone = Pinecone(api_key=API_CONFIG["pinecone"]["api_key"])
            self.index = self.pinecone.Index(API_CONFIG["pinecone"]["index_name"])
            self.embedding_model = API_CONFIG["pinecone"]["embedding_model"]
            self.top_k = API_CONFIG["pinecone"]["top_k"]
            
            logger.info(f"Initialized {self.model_name} classifier with Pinecone RAG")
        except Exception as e:
            logger.error(f"Failed to initialize classifier: {str(e)}")
            raise RuntimeError("Critical: Could not initialize message classifier")

    def _get_embedding(self, text: str) -> list:
        """Get embedding for the input text using OpenAI's embedding model"""
        try:
            response = self.client.embeddings.create(
                input=text,
                model=self.embedding_model
            )
            return response.data[0].embedding
        except Exception as e:
            logger.error(f"Error getting embedding: {str(e)}")
            raise

    def _get_relevant_context(self, text: str) -> tuple:
        """
        Retrieve relevant context from Pinecone and return explanation and similarity
        """
        try:
            # Get embedding for query
            query_embedding = self._get_embedding(text)
            
            # Search in Pinecone
            results = self.index.query(
                vector=query_embedding,
                top_k=self.top_k,
                include_metadata=True
            )
            
            if not results.matches:
                return "", "Phishing/Non-Phishing", 0
            
            match = results.matches[0]  # Get the most similar result
            explanation = match.metadata.get('explanation', '')
            label = match.metadata.get('label', 'Phishing/Non-Phishing')
            similarity = match.score * 100
            
            return explanation, label, similarity
            
        except Exception as e:
            logger.error(f"Error retrieving context: {str(e)}")
            return "", "Phishing/Non-Phishing", 0

    def _analyze_with_rag(self, text: str, explanation: str, label: str, similarity: float) -> Dict[str, Any]:
        """Use RAG context to analyze the message"""
        try:
            # If similarity is high enough and label is clear, use the RAG context
            if similarity > 70 and label == 'Non-Phishing':
                return {
                    "is_phishing": False,
                    "confidence": 0.9,
                    "indicators": {
                        "suspicious": [],
                        "legitimate": ["High similarity with verified legitimate message"]
                    },
                    "explanation": "This message matches patterns of legitimate communications."
                }
            
            # For all other cases, use RAG analysis prompt
            prompt = RAG_ANALYSIS_PROMPT.format(
                text=text,
                explanation=explanation,
                similarity=similarity
            )

            # Get analysis from O3-mini
            completion = self.client.chat.completions.create(
                model=API_CONFIG["openai"]["model"],
                messages=[
                    {"role": "system", "content": "You are a phishing detection expert. Analyze messages objectively."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            
            # Parse and validate the response
            result = MessageAnalysis.model_validate_json(completion.choices[0].message.content)
            
            return result.model_dump()
            
        except Exception as e:
            logger.error(f"Error in RAG analysis: {str(e)}")
            raise

    async def classify(self, text: str) -> Dict[str, Any]:
        """
        Two-stage message classification:
        1. Use fine-tuned RoBERTa model for initial classification
        2. If RoBERTa flags as phishing, use RAG-enhanced O3-mini for second opinion
        """
        try:
            if not text:
                logger.warning("Received empty text for classification")
                return {
                    "is_phishing": False,
                    "confidence": 0.51,
                    "text_analyzed": ""
                }

            # Stage 1: RoBERTa Classification
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=self.max_length,
                padding=True
            ).to(self.device)

            # Get model prediction
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probabilities = torch.nn.functional.softmax(logits, dim=-1)
                prediction = torch.argmax(probabilities, dim=-1)
                raw_confidence = probabilities[0, prediction[0]].item()
                final_confidence = self._calibrate_confidence(raw_confidence, logits)
                is_phishing = bool(prediction[0].item())

            # If RoBERTa flags as phishing, get RAG-enhanced second opinion
            if is_phishing:
                try:
                    logger.info("optimum flagged as phishing, getting RAG-enhanced second opinion...")
                    
                    # Get relevant context from Pinecone
                    explanation, label, similarity = self._get_relevant_context(text)
                    
                    # Get RAG-enhanced analysis
                    rag_result = self._analyze_with_rag(text, explanation, label, similarity)
                    
                    logger.info(f"RAG-enhanced analysis complete: phishing={rag_result['is_phishing']}, confidence={rag_result['confidence']:.2f}")
                    
                    return {
                        "is_phishing": rag_result["is_phishing"],
                        "confidence": rag_result["confidence"],
                        "text_analyzed": text[:100] + "..." if len(text) > 100 else text,
                        "indicators": rag_result["indicators"],
                        "explanation": rag_result["explanation"],
                        "source": "optimum"
                    }
                    
                except Exception as rag_error:
                    logger.error(f"RAG-enhanced analysis failed: {str(rag_error)}")
                    logger.error("Falling back to RoBERTa's verdict...")
                    # Fall back to RoBERTa's verdict if RAG analysis fails
                    return {
                        "is_phishing": is_phishing,
                        "confidence": final_confidence,
                        "text_analyzed": text[:100] + "..." if len(text) > 100 else text,
                        "source": "roberta_fallback"
                    }
            else:
                # If RoBERTa says NOT phishing, return that verdict
                logger.info(f"Classification complete: phishing=False, confidence={final_confidence:.2f}")
                return {
                    "is_phishing": False,
                    "confidence": final_confidence,
                    "text_analyzed": text[:100] + "..." if len(text) > 100 else text,
                    "source": "optimum"
                }

        except Exception as e:
            logger.error(f"Error in message classification: {str(e)}")
            return {
                "is_phishing": False,  # Safe default
                "confidence": 0.51,
                "error": str(e)
            }

    def _calibrate_confidence(self, raw_confidence: float, logits: torch.Tensor) -> float:
        """Calibrate confidence scores using temperature scaling and thresholds"""
        temperature = 1.5  # Higher temperature = softer probabilities
        scaled_confidence = float(torch.nn.functional.softmax(logits / temperature, dim=-1).max().cpu().numpy())
        
        if scaled_confidence > self.high_confidence_threshold:
            return min(self.max_confidence_cap, 
                      self.high_confidence_threshold + (scaled_confidence - self.high_confidence_threshold) * 0.5)
        elif scaled_confidence < self.min_confidence_threshold:
            return max(0.51, scaled_confidence)
        
        return scaled_confidence 