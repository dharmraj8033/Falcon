#!/usr/bin/env python3
"""
Falcon Setup Script
Creates global falcon command and installs the tool system-wide
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

def create_falcon_executable():
    """Create the global falcon executable"""
    
    # Get the current falcon directory
    falcon_dir = Path(__file__).parent.absolute()
    main_py = falcon_dir / "main.py"
    
    if not main_py.exists():
        print("❌ main.py not found! Run this script from the Falcon directory.")
        return False
    
    # Create falcon executable script
    if os.name == 'nt':  # Windows
        return create_windows_executable(falcon_dir)
    else:  # Unix/Linux/macOS
        return create_unix_executable(falcon_dir)

def create_windows_executable(falcon_dir):
    """Create Windows batch file"""
    try:
        # Find Python executable
        python_exe = sys.executable
        
        # Create batch file content
        batch_content = f'''@echo off
"{python_exe}" "{falcon_dir}\\main.py" %*
'''
        
        # Write to Scripts directory or system PATH
        scripts_dir = Path(python_exe).parent / "Scripts"
        
        if scripts_dir.exists():
            falcon_bat = scripts_dir / "falcon.bat"
            falcon_bat.write_text(batch_content)
            print(f"✅ Created: {falcon_bat}")
            return True
        else:
            # Fallback: create in current directory
            falcon_bat = Path.cwd() / "falcon.bat"
            falcon_bat.write_text(batch_content)
            print(f"✅ Created: {falcon_bat}")
            print("⚠️  Add this directory to your PATH to use 'falcon' globally")
            return True
            
    except Exception as e:
        print(f"❌ Failed to create Windows executable: {e}")
        return False

def create_unix_executable(falcon_dir):
    """Create Unix executable script"""
    try:
        # Create executable script content
        script_content = f'''#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, "{falcon_dir}")
os.chdir("{falcon_dir}")

if __name__ == "__main__":
    from main import main
    main()
'''
        
        # Try to install in user's local bin
        local_bin = Path.home() / ".local" / "bin"
        local_bin.mkdir(parents=True, exist_ok=True)
        
        falcon_script = local_bin / "falcon"
        falcon_script.write_text(script_content)
        falcon_script.chmod(0o755)  # Make executable
        
        print(f"✅ Created: {falcon_script}")
        
        # Check if ~/.local/bin is in PATH
        path_env = os.environ.get('PATH', '')
        if str(local_bin) not in path_env:
            print("⚠️  Add ~/.local/bin to your PATH:")
            print(f"   export PATH=\"$PATH:{local_bin}\"")
            print("   Add this to your ~/.bashrc or ~/.zshrc")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to create Unix executable: {e}")
        return False

def create_desktop_entry():
    """Create desktop entry for Linux"""
    if os.name != 'nt':
        try:
            desktop_dir = Path.home() / ".local" / "share" / "applications"
            desktop_dir.mkdir(parents=True, exist_ok=True)
            
            falcon_dir = Path(__file__).parent.absolute()
            
            desktop_content = f'''[Desktop Entry]
Name=Falcon Scanner
Comment=AI-Enhanced Vulnerability Scanner
Exec={Path.home() / ".local" / "bin" / "falcon"} --help
Icon=application-x-executable
Terminal=true
Type=Application
Categories=Development;Security;
'''
            
            desktop_file = desktop_dir / "falcon-scanner.desktop"
            desktop_file.write_text(desktop_content)
            desktop_file.chmod(0o644)
            
            print(f"✅ Created desktop entry: {desktop_file}")
            
        except Exception as e:
            print(f"⚠️  Could not create desktop entry: {e}")

def update_requirements():
    """Add requests to requirements for updater"""
    req_file = Path(__file__).parent / "requirements.txt"
    
    if req_file.exists():
        content = req_file.read_text()
        if 'requests' not in content and 'aiohttp' not in content:
            # Add requests if not present
            with open(req_file, 'a') as f:
                f.write('\nrequests\n')
            print("✅ Updated requirements.txt")

def main():
    """Main setup function"""
    print("🦅 Falcon Scanner Setup")
    print("=" * 30)
    
    # Update requirements first
    update_requirements()
    
    # Create global executable
    if create_falcon_executable():
        print("\n✅ Falcon setup completed successfully!")
        
        # Create desktop entry on Linux
        if os.name != 'nt':
            create_desktop_entry()
        
        print("\n📋 Usage Examples:")
        print("   falcon --help")
        print("   falcon scan --url https://example.com")
        print("   falcon recon --domain example.com")
        print("   falcon autopilot --domain example.com")
        print("   falcon update")
        
        print("\n🎯 Quick Test:")
        print("   Run: falcon --version")
        
    else:
        print("\n❌ Setup failed!")
        print("💡 You can still use: python main.py")

if __name__ == "__main__":
    main()
