#!/usr/bin/env python3
"""
Falcon AI-Enhanced Vulnerability Scanner
A powerful CLI-based security scanner with integrated AI intelligence

Author: Dharm Raj
License: MIT
"""

import sys
import asyncio
from cli.parser import FalconCLI

def main():
    """Main entry point for Falcon CLI"""
    if sys.version_info < (3, 8):
        print("❌ Falcon requires Python 3.8 or higher")
        sys.exit(1)
    
    cli = FalconCLI()
    
    # Run the CLI parser and execute commands
    try:
        asyncio.run(cli.run())
    except KeyboardInterrupt:
        print("\n🔴 Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
