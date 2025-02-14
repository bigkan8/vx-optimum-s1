"""Process Logger Module

This module handles logging of the analysis process in a user-friendly format,
showing the step-by-step thinking and analysis without exposing internal implementation details.
"""

from typing import List, Dict, Any

class ProcessLogger:
    def __init__(self):
        self.steps: List[Dict[str, Any]] = []
        
    def add_step(self, description: str, findings: Dict[str, Any] = None) -> None:
        """Add a step to the analysis process log"""
        step = {
            "description": description,
            "findings": findings or {}
        }
        self.steps.append(step)
        
    def get_process_narrative(self) -> str:
        """Generate a user-friendly narrative of the analysis process"""
        narrative = ["Here's how I analyzed this message:\n"]
        
        for step in self.steps:
            # Skip initial message analysis step as it's redundant
            if "Analyzing input message" in step["description"]:
                continue
                
            # Handle message classification step
            if "message patterns" in step["description"].lower():
                if step["findings"].get("confidence"):
                    narrative.append("1. First, I analyzed the message content and writing patterns.")
                continue
                
            # Handle URL analysis step
            if "URL analysis" in step["description"]:
                if step["findings"].get("technical_indicators"):
                    narrative.append("2. I found a URL in the message and performed a technical security analysis on it.")
                continue
                
            # Handle fact verification step
            if "factual claims" in step["description"]:
                facts = step["findings"].get("verified_facts", [])
                if facts:
                    narrative.append("3. I checked the factual claims in the message against reliable sources.")
                continue
                
            # Handle character selection step - skip this as it's not relevant to the user
            if "Generating analysis as" in step["description"]:
                continue
        
        # Only return narrative if we have meaningful steps
        if len(narrative) > 1:  # More than just the intro line
            return "\n".join(narrative)
        return ""  # Return empty string if no meaningful steps to show

    def clear(self) -> None:
        """Clear the process log"""
        self.steps = [] 