"""
Logging Configuration and Setup
"""

import os
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    # Fallback color codes
    class Fore:
        CYAN = '\033[96m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        MAGENTA = '\033[95m'
    
    class Style:
        RESET_ALL = '\033[0m'
    
    COLORAMA_AVAILABLE = False

class ColoredFormatter(logging.Formatter):
    """Custom formatter that adds colors to log levels"""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m'   # Magenta
    } if not COLORAMA_AVAILABLE else {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.MAGENTA
    }
    
    RESET = '\033[0m' if not COLORAMA_AVAILABLE else Style.RESET_ALL
    
    def format(self, record):
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"
        return super().format(record)

class FalconLogger:
    """Custom logger for Falcon with multiple handlers"""
    
    def __init__(self, name: str = 'falcon', level: str = 'INFO'):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        
        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        """Setup console and file handlers"""
        # Console handler with colors
        console_handler = logging.StreamHandler()
        console_formatter = ColoredFormatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(logging.INFO)
        
        # File handler
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f'falcon_{datetime.now().strftime("%Y%m%d")}.log'
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, 
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        
        file_formatter = logging.Formatter(
            '%(asctime)s | %(name)s | %(levelname)s | %(funcName)s:%(lineno)d | %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(logging.DEBUG)
        
        # Add handlers
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
    
    def debug(self, message: str):
        self.logger.debug(message)
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def critical(self, message: str):
        self.logger.critical(message)
    
    def success(self, message: str):
        """Log success message with green color"""
        if COLORAMA_AVAILABLE:
            self.logger.info(f"{Fore.GREEN}✅ {message}{Style.RESET_ALL}")
        else:
            self.logger.info(f"✅ {message}")
    
    def vulnerability_found(self, vuln_type: str, severity: str, url: str):
        """Log vulnerability finding"""
        severity_colors = {
            'CRITICAL': Fore.RED if COLORAMA_AVAILABLE else '\033[31m',
            'HIGH': Fore.RED if COLORAMA_AVAILABLE else '\033[31m',
            'MEDIUM': Fore.YELLOW if COLORAMA_AVAILABLE else '\033[33m',
            'LOW': Fore.GREEN if COLORAMA_AVAILABLE else '\033[32m',
            'INFO': Fore.BLUE if COLORAMA_AVAILABLE else '\033[34m'
        }
        
        color = severity_colors.get(severity.upper(), '')
        reset = Style.RESET_ALL if COLORAMA_AVAILABLE else '\033[0m'
        
        message = f"{color}🎯 {vuln_type} [{severity.upper()}] found at {url}{reset}"
        self.logger.warning(message)
    
    def scan_progress(self, current: int, total: int, target: str):
        """Log scan progress"""
        percentage = (current / total) * 100 if total > 0 else 0
        self.logger.info(f"📊 Progress: {current}/{total} ({percentage:.1f}%) - {target}")
    
    def ai_insight(self, insight_type: str, message: str, confidence: Optional[float] = None):
        """Log AI-generated insights"""
        conf_str = f" (confidence: {confidence:.1f}%)" if confidence else ""
        self.logger.info(f"🧠 AI {insight_type}: {message}{conf_str}")
    
    def tool_execution(self, tool_name: str, command: str, status: str):
        """Log tool execution"""
        status_emoji = "✅" if status == "success" else "❌"
        self.logger.info(f"{status_emoji} {tool_name}: {command} - {status}")
    
    def http_request(self, method: str, url: str, status_code: int, response_time: float):
        """Log HTTP requests"""
        status_color = ""
        if COLORAMA_AVAILABLE:
            if 200 <= status_code < 300:
                status_color = Fore.GREEN
            elif 300 <= status_code < 400:
                status_color = Fore.YELLOW
            elif 400 <= status_code < 500:
                status_color = Fore.RED
            elif status_code >= 500:
                status_color = Fore.MAGENTA
        
        reset = Style.RESET_ALL if COLORAMA_AVAILABLE else ""
        self.logger.debug(f"🌐 {method} {url} - {status_color}{status_code}{reset} ({response_time:.2f}s)")

def setup_logger(name: str = 'falcon', level: str = 'INFO', 
                log_file: Optional[str] = None) -> FalconLogger:
    """Setup and return a configured logger"""
    return FalconLogger(name, level)

def setup_debug_logger() -> FalconLogger:
    """Setup logger for debug mode"""
    return FalconLogger('falcon-debug', 'DEBUG')

def setup_quiet_logger() -> FalconLogger:
    """Setup minimal logger for quiet mode"""
    logger = FalconLogger('falcon-quiet', 'ERROR')
    # Remove console handler for quiet mode
    for handler in logger.logger.handlers[:]:
        if isinstance(handler, logging.StreamHandler) and handler.stream.name == '<stderr>':
            logger.logger.removeHandler(handler)
    return logger

# Create module-level logger instances
default_logger = setup_logger()
debug_logger = setup_debug_logger()
quiet_logger = setup_quiet_logger()
