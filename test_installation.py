#!/usr/bin/env python3
"""
Simple test to verify Falcon AI installation
"""

import sys
import os
import asyncio
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_imports():
    """Test that all core modules can be imported"""
    print("🧪 Testing imports...")
    
    try:
        # Test CLI modules
        from cli.banner import print_banner
        from cli.parser import create_parser
        print("   ✅ CLI modules")
        
        # Test core modules  
        from core.config import config
        from core.logger import setup_logger
        from core.scanner import FalconScanner
        print("   ✅ Core modules")
        
        # Test AI engine
        from ai_engine.ai_core import AIEngine
        print("   ✅ AI engine")
        
        # Test modules
        from modules.subdomain_finder import SubdomainFinder
        from modules.technology_detector import TechnologyDetector
        from modules.parameter_finder import ParameterFinder
        from modules.crawler import WebCrawler
        print("   ✅ Security modules")
        
        # Test output
        from output.report_generator import ReportGenerator
        print("   ✅ Output modules")
        
        return True
        
    except ImportError as e:
        print(f"   ❌ Import error: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality"""
    print("🔧 Testing basic functionality...")
    
    try:
        # Test configuration
        from core.config import config
        user_agent = config.get_user_agent()
        print(f"   ✅ Config loaded (User-Agent: {user_agent[:20]}...)")
        
        # Test logger
        from core.logger import setup_logger
        logger = setup_logger()
        logger.info("Test log message")
        print("   ✅ Logging system")
        
        # Test AI engine initialization
        from ai_engine.ai_core import AIEngine
        ai_engine = AIEngine()
        print("   ✅ AI engine initialized")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Functionality test failed: {e}")
        return False

async def test_async_functionality():
    """Test async functionality"""
    print("⚡ Testing async functionality...")
    
    try:
        # Test HTTP client
        from core.http_client import HTTPClient
        
        async with HTTPClient() as client:
            # Test a simple request (to a reliable service)
            response = await client.get('https://httpbin.org/user-agent')
            if response['status_code'] == 200:
                print("   ✅ HTTP client working")
            else:
                print(f"   ⚠️  HTTP client returned status {response['status_code']}")
        
        # Test scanner initialization
        from core.scanner import FalconScanner
        from ai_engine.ai_core import AIEngine
        
        ai_engine = AIEngine()
        scanner = FalconScanner(ai_engine)
        print("   ✅ Scanner initialized")
        
        await scanner.cleanup()
        print("   ✅ Scanner cleanup")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Async test failed: {e}")
        return False

def test_cli():
    """Test CLI functionality"""
    print("💻 Testing CLI...")
    
    try:
        from cli.banner import print_banner
        from cli.parser import create_parser
        
        # Test parser
        parser = create_parser()
        args = parser.parse_args(['scan', '--url', 'https://example.com'])
        print(f"   ✅ CLI parser (command: {args.command})")
        
        # Test banner (capture output)
        import io
        import contextlib
        
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            print_banner()
        banner_output = f.getvalue()
        
        if 'FALCON' in banner_output:
            print("   ✅ Banner display")
        else:
            print("   ⚠️  Banner might have issues")
        
        return True
        
    except Exception as e:
        print(f"   ❌ CLI test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🦅 Falcon AI Installation Test")
    print("=" * 40)
    
    tests_passed = 0
    total_tests = 4
    
    # Run tests
    if test_imports():
        tests_passed += 1
    
    if test_basic_functionality():
        tests_passed += 1
    
    if test_cli():
        tests_passed += 1
    
    # Run async test
    try:
        if asyncio.run(test_async_functionality()):
            tests_passed += 1
    except Exception as e:
        print(f"   ❌ Async test setup failed: {e}")
    
    # Results
    print("\n" + "=" * 40)
    print(f"Tests passed: {tests_passed}/{total_tests}")
    
    if tests_passed == total_tests:
        print("🎉 All tests passed! Falcon AI is ready to use.")
        print("\nQuick start:")
        print("  python main.py --help")
        print("  python main.py scan --url https://example.com")
        return True
    else:
        print("⚠️  Some tests failed. Check the errors above.")
        print("💡 Try running: python setup.py")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
