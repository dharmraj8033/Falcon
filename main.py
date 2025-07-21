#!/usr/bin/env python3
"""
Falcon AI - Advanced AI-Enhanced Vulnerability Scanner
A production-ready CLI tool for web application security testing
"""

import sys
import os
import argparse
import asyncio
import signal
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from cli.banner import print_banner
from cli.parser import create_parser
from core.scanner import FalconScanner
from core.config import Config
from core.logger import setup_logger
from ai_engine.ai_core import AIEngine

__version__ = "1.0.0"
__author__ = "Falcon Security Team"

class FalconCLI:
    def __init__(self):
        self.scanner = None
        self.ai_engine = None
        self.logger = None
        
    async def initialize(self):
        """Initialize the scanner components"""
        self.logger = setup_logger()
        self.ai_engine = AIEngine()
        self.scanner = FalconScanner(ai_engine=self.ai_engine)
        
    def signal_handler(self, signum, frame):
        """Handle graceful shutdown"""
        print("\n[!] Scan interrupted by user. Cleaning up...")
        if self.scanner:
            asyncio.create_task(self.scanner.cleanup())
        sys.exit(0)
        
    async def run(self, args):
        """Main execution function"""
        await self.initialize()
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            if args.command == 'scan':
                await self.handle_scan(args)
            elif args.command == 'fuzz':
                await self.handle_fuzz(args)
            elif args.command == 'tech':
                await self.handle_tech(args)
            elif args.command == 'update':
                await self.handle_update(args)
            elif args.command == 'ai-train':
                await self.handle_ai_train(args)
            elif args.command == 'version':
                print(f"Falcon AI v{__version__}")
            else:
                # Direct URL scan
                await self.handle_direct_scan(args)
                
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
        except Exception as e:
            self.logger.error(f"Error during execution: {e}")
            if args.debug:
                import traceback
                traceback.print_exc()
        finally:
            if self.scanner:
                await self.scanner.cleanup()
    
    async def handle_scan(self, args):
        """Handle scan command"""
        await self.scanner.scan(
            target=args.url,
            modules=args.modules,
            output_format=args.output,
            output_file=args.output_file,
            verbose=args.verbose,
            autopilot=args.autopilot
        )
    
    async def handle_fuzz(self, args):
        """Handle fuzz command"""
        await self.scanner.fuzz(
            target=args.url,
            wordlist=args.wordlist,
            parameters=args.parameters
        )
    
    async def handle_tech(self, args):
        """Handle tech detection command"""
        await self.scanner.detect_technology(args.url)
    
    async def handle_update(self, args):
        """Handle update command"""
        await self.scanner.update_components()
        if args.ai_data:
            await self.ai_engine.update_training_data()
    
    async def handle_ai_train(self, args):
        """Handle AI training command"""
        await self.ai_engine.train_model(
            data_sources=args.sources,
            epochs=args.epochs
        )
    
    async def handle_direct_scan(self, args):
        """Handle direct URL scan"""
        await self.scanner.scan(
            target=args.url,
            output_format=args.output,
            output_file=args.output_file,
            verbose=args.verbose
        )

def main():
    """Main entry point"""
    print_banner()
    
    parser = create_parser()
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    # Create output directory if specified
    if hasattr(args, 'output_file') and args.output_file:
        os.makedirs(os.path.dirname(args.output_file), exist_ok=True)
    
    # Run the CLI
    cli = FalconCLI()
    
    # Use asyncio.run for Python 3.7+
    if sys.version_info >= (3, 7):
        asyncio.run(cli.run(args))
    else:
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(cli.run(args))
        finally:
            loop.close()

if __name__ == "__main__":
    main()
