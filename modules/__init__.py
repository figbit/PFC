"""
Nessus DOCX Report Generator - Core Modules

This package contains the core modules for parsing Nessus XML files
and generating DOCX reports.
"""

from .nessus_parser import NessusParser
from .docx_generator import DocxGenerator

__all__ = ['NessusParser', 'DocxGenerator']
__version__ = '1.0.0' 