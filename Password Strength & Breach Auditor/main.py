"""
Password Strength Checker & Breach Auditor (k-Anonymity)
Entry point of the application.
"""

import sys
import os

# Add root folder to sys.path so submodules import seamlessly
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from ui.app_qt import main

if __name__ == "__main__":
    main()
