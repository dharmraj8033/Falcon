#!/usr/bin/env python3
"""
Basic functionality tests for Falcon AI
"""

import sys
import os
import asyncio
import unittest
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

class TestFalconBasics(unittest.TestCase):
    """Basic tests for Falcon AI functionality"""
    
    def test_banner_import(self):
        """Test banner module import"""
        try:
            from cli.banner import print_banner, FALCON_ASCII
            self.assertIsNotNone(FALCON_ASCII)
            print("✅ Banner module imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import banner module: {e}")
    
    def test_config_loading(self):
        """Test configuration loading"""
        try:
            from core.config import config
            self.assertIsNotNone(config)
            print("✅ Config module loaded successfully")
        except Exception as e:
            self.fail(f"Failed to load config: {e}")
    
    def test_ai_engine_init(self):
        """Test AI engine initialization"""
        try:
            from ai_engine.ai_core import AIEngine
            ai_engine = AIEngine()
            self.assertIsNotNone(ai_engine)
            print("✅ AI engine initialized successfully")
        except Exception as e:
            self.fail(f"Failed to initialize AI engine: {e}")
    
    def test_scanner_init(self):
        """Test scanner initialization"""
        try:
            from core.scanner import FalconScanner
            scanner = FalconScanner()
            self.assertIsNotNone(scanner)
            print("✅ Scanner initialized successfully")
        except Exception as e:
            self.fail(f"Failed to initialize scanner: {e}")

def run_basic_tests():
    """Run basic functionality tests"""
    print("🧪 Running basic functionality tests...")
    
    # Test imports
    try:
        import colorama
        print("   ✅ colorama available")
    except ImportError:
        print("   ❌ colorama not available (using fallback)")
    
    try:
        import aiohttp
        print("   ✅ aiohttp available")
    except ImportError:
        print("   ❌ aiohttp not available (using fallback)")
    
    try:
        import yaml
        print("   ✅ yaml available")
    except ImportError:
        print("   ❌ yaml not available (using fallback)")
    
    # Test core functionality
    try:
        from core.config import config
        print("   ✅ Configuration loaded")
    except Exception as e:
        print(f"   ❌ Configuration failed: {e}")
        return False
    
    try:
        from ai_engine.ai_core import AIEngine
        ai_engine = AIEngine()
        print("   ✅ AI engine initialized")
    except Exception as e:
        print(f"   ❌ AI engine failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("🦅 Falcon AI - Basic Tests")
    print("=" * 40)
    
    success = run_basic_tests()
    
    if success:
        print("\n✅ All basic tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)