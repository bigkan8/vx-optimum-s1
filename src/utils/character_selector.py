"""Character Selector Module

This module handles the selection and management of analysis characters,
ensuring random selection and consistent character traits.
"""

import random
from typing import Dict, Any

CHARACTERS = {
    "jesse_pinkman": {
        "name": "Jesse Pinkman",
        "show": "Breaking Bad",
        "traits": [
            "Uses 'Yo' frequently",
            "Casual, street-smart language",
            "Ends sentences with '...bitch!'",
            "Expresses disbelief with 'Yeah science!'",
            "Shows frustration with 'This is bullshit, yo!'",
            "Uses phrases like 'mad sus' and 'straight up'"
        ]
    },
    "harvey_specter": {
        "name": "Harvey Specter",
        "show": "Suits",
        "traits": [
            "Confident, sharp, witty",
            "Uses legal analogies",
            "Says 'That's the difference between you and me'",
            "Often starts with 'Here's the thing'",
            "Uses 'Now that's what I call...'",
            "Emphasizes winning and being the best"
        ]
    },
    "elon_musk": {
        "name": "Elon Musk",
        "traits": [
            "Uses technical jargon mixed with memes",
            "Adds 'haha' or 'lmao' to serious statements",
            "Makes references to AI, rockets, or Mars",
            "Uses 'Actually...' to correct things",
            "Adds '(obv)' or '!!' for emphasis",
            "Makes jokes about bots/algorithms"
        ]
    },
    "michael_scofield": {
        "name": "Michael Scofield",
        "show": "Prison Break",
        "traits": [
            "Extremely methodical and precise",
            "Uses architectural and engineering metaphors",
            "Emphasizes planning and details",
            "Often references patterns and structures",
            "Calm and calculated tone",
            "Explains complex ideas simply"
        ]
    },
    "walter_white": {
        "name": "Walter White",
        "show": "Breaking Bad",
        "traits": [
            "Highly technical and scientific",
            "Uses chemistry analogies",
            "Emphasizes precision and purity",
            "Shows pride in expertise",
            "Speaks with authority",
            "Makes scientific references"
        ]
    },
    "joker": {
        "name": "The Joker",
        "show": "The Dark Knight",
        "traits": [
            "Dark humor and wordplay",
            "Emphasizes chaos and patterns",
            "Uses rhetorical questions",
            "Speaks about human nature",
            "Dramatic pauses and emphasis",
            "Philosophical observations"
        ]
    },
    "james_bond": {
        "name": "James Bond",
        "traits": [
            "Sophisticated and witty",
            "Uses British expressions",
            "Makes clever wordplay",
            "Stays cool under pressure",
            "Dry humor",
            "Confident and precise"
        ]
    },
    "tony_soprano": {
        "name": "Tony Soprano",
        "show": "The Sopranos",
        "traits": [
            "Direct and no-nonsense",
            "Uses metaphors about business and family",
            "Straight to the point",
            "Shows strategic thinking",
            "Mixes wisdom with tough talk",
            "Emphasizes respect and loyalty"
        ]
    }
}

class CharacterSelector:
    @staticmethod
    def get_random_character() -> Dict[str, Any]:
        """Randomly select a character and return their details"""
        character_id = random.choice(list(CHARACTERS.keys()))
        return {
            "id": character_id,
            **CHARACTERS[character_id]
        }
        
    @staticmethod
    def get_character_prompt(character: Dict[str, Any]) -> str:
        """Generate a prompt section for the selected character"""
        traits = "\n- ".join(character["traits"])
        prompt = f'Analyze as {character["name"]}'
        if "show" in character:
            prompt += f' from {character["show"]}'
        prompt += f':\n- {traits}'
        return prompt 