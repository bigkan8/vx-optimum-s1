"""Process Logger Module

This module handles logging of the analysis process in a user-friendly format,
showing the step-by-step thinking and analysis without exposing internal implementation details.
"""

from typing import List, Dict, Any
import json
from ..utils.logger import Logger

logger = Logger(__name__)

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
        logger.debug(f"Added process step: {json.dumps(step, indent=2)}")
        
    def get_process_narrative(self) -> str:
        """Generate a user-friendly narrative of the analysis process"""
        narrative = ["Analysis Process:\n"]
        
        for i, step in enumerate(self.steps, 1):
            narrative.append(f"\nStep {i}: {step['description']}")
            if step['findings']:
                narrative.append("Findings:")
                for key, value in step['findings'].items():
                    if isinstance(value, (list, dict)):
                        narrative.append(f"- {key}:")
                        if isinstance(value, list):
                            for item in value:
                                narrative.append(f"  • {item}")
                        else:  # dict
                            for k, v in value.items():
                                narrative.append(f"  • {k}: {v}")
                    else:
                        narrative.append(f"- {key}: {value}")
                narrative.append("")
        
        return "\n".join(narrative)

    def clear(self) -> None:
        """Clear the process log"""
        self.steps = [] 