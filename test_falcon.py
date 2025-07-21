#!/usr/bin/env python3
"""
Falcon AI - Standalone Test Script
This script tests basic functionality without requiring external dependencies
"""

import sys
import os
import asyncio
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

def print_banner():
    """Print simple banner without colors"""
    print("=" * 60)
    print("    FALCON AI - Vulnerability Scanner Test")
    print("    🦅 AI-Enhanced Security Testing")
    print("=" * 60)

def test_basic_imports():
    """Test if basic Python modules work"""
    print("🔍 Testing basic imports...")
    
    try:
        import json
        import re
        import time
        import urllib.request
        import asyncio
        import pathlib
        print("✅ Basic Python modules imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Basic import failed: {e}")
        return False

def test_falcon_modules():
    """Test Falcon modules"""
    print("🦅 Testing Falcon modules...")
    
    try:
        # Test configuration
        from core.config import Config
        config = Config()
        print("✅ Configuration module loaded")
        
        # Test AI engine
        from ai_engine.ai_core import AIEngine
        ai_engine = AIEngine()
        print("✅ AI engine initialized")
        
        # Test banner
        from cli.banner import print_banner as falcon_banner
        print("✅ CLI banner module loaded")
        
        return True
        
    except Exception as e:
        print(f"❌ Falcon module test failed: {e}")
        return False

async def test_async_functionality():
    """Test async functionality"""
    print("⚡ Testing async functionality...")
    
    try:
        # Simple async test
        await asyncio.sleep(0.1)
        print("✅ Async functionality working")
        return True
    except Exception as e:
        print(f"❌ Async test failed: {e}")
        return False

def test_file_operations():
    """Test file operations"""
    print("📁 Testing file operations...")
    
    try:
        # Create test directory
        test_dir = Path("test_output")
        test_dir.mkdir(exist_ok=True)
        
        # Create test file
        test_file = test_dir / "test.txt"
        test_file.write_text("Falcon test")
        
        # Read test file
        content = test_file.read_text()
        assert content == "Falcon test"
        
        # Clean up
        test_file.unlink()
        test_dir.rmdir()
        
        print("✅ File operations working")
        return True
        
    except Exception as e:
        print(f"❌ File operations test failed: {e}")
        return False

def test_network_availability():
    """Test basic network functionality"""
    print("🌐 Testing network availability...")
    
    try:
        import urllib.request
        import socket
        
        # Test DNS resolution
        socket.gethostbyname('google.com')
        print("✅ DNS resolution working")
        
        # Test HTTP request (simple)
        response = urllib.request.urlopen('http://httpbin.org/get', timeout=5)
        if response.getcode() == 200:
            print("✅ HTTP requests working")
            return True
        else:
            print("⚠️  HTTP request returned non-200 status")
            return False
            
    except Exception as e:
        print(f"⚠️  Network test failed (this is OK if offline): {e}")
        return False

def create_sample_scan_data():
    """Create sample scan data for testing"""
    print("📊 Creating sample scan data...")
    
    try:
        sample_data = {
            "target": "https://example.com",
            "vulnerabilities": [
                {
                    "type": "XSS",
                    "severity": "HIGH",
                    "url": "https://example.com/search?q=<script>alert('xss')</script>",
                    "description": "Reflected XSS vulnerability found",
                    "evidence": "<script>alert('xss')</script>"
                }
            ],
            "technologies": {
                "web_servers": [
                    {"name": "Apache", "version": "2.4.41", "confidence": 90}
                ],
                "programming_languages": [
                    {"name": "PHP", "version": "7.4", "confidence": 85}
                ]
            },
            "scan_stats": {
                "duration": 45.2,
                "urls_scanned": 150,
                "vulnerabilities_found": 1
            }
        }
        
        # Create output directory
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        
        # Save sample data
        sample_file = output_dir / "sample_scan.json"
        with open(sample_file, 'w') as f:
            json.dump(sample_data, f, indent=2)
        
        print(f"✅ Sample scan data created: {sample_file}")
        return True
        
    except Exception as e:
        print(f"❌ Sample data creation failed: {e}")
        return False

def run_mini_vulnerability_test():
    """Run a mini vulnerability detection test"""
    print("🎯 Running mini vulnerability test...")
    
    try:
        # Sample vulnerable code patterns
        test_responses = [
            "<script>alert('xss')</script>",  # XSS
            "MySQL syntax error",             # SQLi
            "Warning: mysql_fetch_array()",   # SQLi
            "java.lang.NullPointerException", # Java error
            "Fatal error: Call to undefined function"  # PHP error
        ]
        
        # Simple pattern matching (like a basic vulnerability detector)
        xss_patterns = [r'<script.*?>', r'javascript:', r'on\w+\s*=']
        sqli_patterns = [r'MySQL.*error', r'Warning.*mysql', r'ORA-\d+']
        
        found_vulns = []
        
        for response in test_responses:
            # Check XSS
            for pattern in xss_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    found_vulns.append(("XSS", response))
                    break
            
            # Check SQLi
            for pattern in sqli_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    found_vulns.append(("SQLi", response))
                    break
        
        print(f"✅ Mini vulnerability test completed - Found {len(found_vulns)} potential issues")
        for vuln_type, evidence in found_vulns:
            print(f"   🎯 {vuln_type}: {evidence[:50]}...")
        
        return True
        
    except Exception as e:
        print(f"❌ Vulnerability test failed: {e}")
        return False

async def main():
    """Main test function"""
    print_banner()
    
    print(f"🐍 Python version: {sys.version}")
    print(f"📁 Working directory: {os.getcwd()}")
    print(f"🔧 Platform: {sys.platform}")
    print()
    
    tests = [
        ("Basic Imports", test_basic_imports),
        ("File Operations", test_file_operations),
        ("Falcon Modules", test_falcon_modules),
        ("Sample Data Creation", create_sample_scan_data),
        ("Mini Vulnerability Test", run_mini_vulnerability_test),
    ]
    
    # Run async test separately
    async_test_passed = await test_async_functionality()
    
    # Run network test (optional)
    network_test_passed = test_network_availability()
    
    # Run main tests
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 Running: {test_name}")
        try:
            if test_func():
                passed += 1
            else:
                print(f"❌ {test_name} failed")
        except Exception as e:
            print(f"❌ {test_name} crashed: {e}")
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    print(f"✅ Passed: {passed}/{total} core tests")
    print(f"⚡ Async: {'✅ Working' if async_test_passed else '❌ Failed'}")
    print(f"🌐 Network: {'✅ Working' if network_test_passed else '⚠️  Offline/Failed'}")
    
    if passed == total and async_test_passed:
        print("\n🎉 All critical tests passed! Falcon AI is ready to use.")
        print("\n🚀 Try running:")
        print("   python main.py --help")
        print("   python main.py scan --url https://httpbin.org/get")
    else:
        print(f"\n⚠️  Some tests failed. Check the errors above.")
        print("💡 Try installing missing dependencies or use Docker.")
    
    print("\n🦅 Falcon AI Test Complete")

if __name__ == "__main__":
    # Run with asyncio
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test runner failed: {e}")
        print("🔧 This might be due to missing dependencies")
