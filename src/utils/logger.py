import logging
import sys
from typing import Optional
from pathlib import Path

class Logger:
    """
    Centralized logging configuration for the phishing detection system.
    Handles both file and console logging with different levels.
    """
    
    def __init__(self, name: str, log_file: Optional[str] = "phishing_detector.log"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Prevent duplicate handlers
        if not self.logger.handlers:
            # Console handler (INFO and above)
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_format = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(console_format)
            self.logger.addHandler(console_handler)
            
            # File handler (ERROR and above)
            if log_file:
                log_path = Path("logs")
                log_path.mkdir(exist_ok=True)
                file_handler = logging.FileHandler(log_path / log_file)
                file_handler.setLevel(logging.ERROR)
                file_format = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                file_handler.setFormatter(file_format)
                self.logger.addHandler(file_handler)

    def info(self, msg: str):
        """Log info level message"""
        self.logger.info(msg)

    def error(self, msg: str):
        """Log error level message"""
        self.logger.error(msg)

    def warning(self, msg: str):
        """Log warning level message"""
        self.logger.warning(msg)

    def debug(self, msg: str):
        """Log debug level message"""
        self.logger.debug(msg) 