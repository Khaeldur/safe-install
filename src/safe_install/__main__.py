"""Allow running as: python -m safe_install"""
from .cli import main
import sys

if __name__ == '__main__':
    sys.exit(main())
