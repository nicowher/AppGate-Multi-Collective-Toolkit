"""Toolkit menu implementations.

Each tool is launched from app/main.py. Shared code is in api/, ssh/, and
core/ (not loose files under app/). Adding app/ to sys.path here (and
again at the top of each tool file) lets `python app/tools/<name>.py` work
the same as `python app/main.py N`.
"""
import os
import sys

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)
