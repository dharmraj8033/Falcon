"""
Falcon AI CLI Package
"""

from .main import main
from .core.scanner import FalconScanner
from .ai_engine.ai_core import AIEngine
from .core.config import config

__version__ = "1.0.0"
__author__ = "Falcon Security Team"
__email__ = "security@falcon.ai"
__description__ = "AI-Enhanced Vulnerability Scanner"

__all__ = [
    'main',
    'FalconScanner', 
    'AIEngine',
    'config'
]
