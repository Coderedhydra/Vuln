"""
VulnHunter Agents Module
LLM-powered autonomous vulnerability hunting agents
"""

from .ollama_agent import OllamaAgent, VulnHunterAgent
from .prompts import SystemPrompts

__all__ = [
    'OllamaAgent',
    'VulnHunterAgent',
    'SystemPrompts',
]
