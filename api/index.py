"""
Vercel Serverless Function entry point.
Exposes the FastAPI application to Vercel's Python runtime.
"""
import sys
import os

# Add root directory to path so core modules can be imported
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import app
