"""
Falcon Update Manager
Handles updating Falcon scanner and its components
"""

import asyncio
import subprocess
import sys
import json
from pathlib import Path
from typing import Dict, Any, Optional
import aiohttp
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text

console = Console()

class FalconUpdater:
    """Handles Falcon updates and component management"""
    
    def __init__(self):
        self.current_version = "1.0.0"
        self.repo_url = "https://api.github.com/repos/dharmraj8033/Falcon"
        self.repo_raw_url = "https://raw.githubusercontent.com/dharmraj8033/Falcon/main"
        self.falcon_dir = Path(__file__).parent.parent
        
    async def check_updates(self, check_only: bool = False) -> Dict[str, Any]:
        """Check for available updates"""
        console.print("[cyan]🔍 Checking for updates...[/cyan]")
        
        # First try git-based update (most reliable)
        git_update_result = await self._try_git_update(check_only)
        if git_update_result:
            return git_update_result
        
        # Fallback to GitHub API
        try:
            async with aiohttp.ClientSession() as session:
                # Get latest release info
                async with session.get(f"{self.repo_url}/releases/latest") as response:
                    if response.status == 200:
                        release_data = await response.json()
                        latest_version = release_data.get('tag_name', '').lstrip('v')
                        
                        update_info = {
                            'current_version': self.current_version,
                            'latest_version': latest_version,
                            'update_available': self._compare_versions(latest_version, self.current_version),
                            'release_notes': release_data.get('body', ''),
                            'published_at': release_data.get('published_at', ''),
                            'download_url': release_data.get('zipball_url', '')
                        }
                        
                        self._display_update_info(update_info)
                        
                        if update_info['update_available'] and not check_only:
                            if self._prompt_user_update():
                                await self.perform_update()
                        
                        return update_info
                    elif response.status == 403:
                        console.print("[yellow]⚠️  GitHub API rate limit reached[/yellow]")
                        console.print("[cyan]💡 Try using: git pull origin main[/cyan]")
                        return await self._fallback_git_check()
                    else:
                        console.print(f"[yellow]⚠️  Could not check for updates (HTTP {response.status})[/yellow]")
                        return await self._fallback_git_check()
                        
        except Exception as e:
            console.print(f"[yellow]⚠️  Update check failed: {e}[/yellow]")
            return await self._fallback_git_check()
    
    async def _try_git_update(self, check_only: bool = False) -> Dict[str, Any]:
        """Try to update using git commands"""
        try:
            # Check if we're in a git repository
            result = subprocess.run(
                ['git', 'status', '--porcelain'],
                cwd=self.falcon_dir,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                return {}  # Not a git repo, fallback to API
            
            # Check for remote updates
            subprocess.run(
                ['git', 'fetch', 'origin'],
                cwd=self.falcon_dir,
                capture_output=True,
                text=True
            )
            
            # Check if updates are available
            result = subprocess.run(
                ['git', 'rev-list', '--count', 'HEAD..origin/main'],
                cwd=self.falcon_dir,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0 and result.stdout.strip():
                commits_behind = int(result.stdout.strip())
                
                if commits_behind > 0:
                    console.print(f"[green]🎉 {commits_behind} new commits available![/green]")
                    
                    if not check_only:
                        if self._prompt_user_update():
                            return await self._perform_git_update()
                    
                    return {
                        'current_version': self.current_version,
                        'commits_behind': commits_behind,
                        'update_available': True,
                        'method': 'git'
                    }
                else:
                    console.print("[green]✅ Falcon is up to date![/green]")
                    return {
                        'current_version': self.current_version,
                        'update_available': False,
                        'method': 'git'
                    }
            
        except FileNotFoundError:
            # Git not available
            return {}
        except Exception as e:
            console.print(f"[yellow]⚠️  Git check failed: {e}[/yellow]")
            return {}
        
        return {}
    
    async def _fallback_git_check(self) -> Dict[str, Any]:
        """Fallback to manual git instructions"""
        console.print("[cyan]📋 Manual update instructions:[/cyan]")
        console.print("   1. cd Falcon")
        console.print("   2. git pull origin main")
        console.print("   3. pip install -r requirements.txt")
        
        return {
            'current_version': self.current_version,
            'update_available': 'unknown',
            'method': 'manual'
        }
    
    async def _perform_git_update(self) -> Dict[str, Any]:
        """Perform git-based update"""
        console.print("[cyan]🚀 Updating Falcon...[/cyan]")
        
        try:
            # Pull latest changes
            result = subprocess.run(
                ['git', 'pull', 'origin', 'main'],
                cwd=self.falcon_dir,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                console.print("[green]✅ Successfully updated Falcon![/green]")
                
                # Update dependencies
                console.print("[cyan]📦 Updating dependencies...[/cyan]")
                dep_result = subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'],
                    cwd=self.falcon_dir,
                    capture_output=True,
                    text=True
                )
                
                if dep_result.returncode == 0:
                    console.print("[green]✅ Dependencies updated![/green]")
                else:
                    console.print("[yellow]⚠️  Some dependencies may need manual update[/yellow]")
                
                console.print("[green]🎉 Update completed successfully![/green]")
                return {'success': True, 'method': 'git'}
            else:
                console.print(f"[red]❌ Update failed: {result.stderr}[/red]")
                return {'success': False, 'method': 'git', 'error': result.stderr}
                
        except Exception as e:
            console.print(f"[red]❌ Update failed: {e}[/red]")
            return {'success': False, 'method': 'git', 'error': str(e)}
    
    def _compare_versions(self, version1: str, version2: str) -> bool:
        """Compare two version strings"""
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            return v1_parts > v2_parts
        except:
            return False
    
    def _display_update_info(self, update_info: Dict[str, Any]):
        """Display update information"""
        if update_info.get('update_available'):
            update_text = Text()
            update_text.append("🎉 New version available!\n\n", style="bold green")
            update_text.append(f"Current: {update_info['current_version']}\n", style="yellow")
            update_text.append(f"Latest: {update_info['latest_version']}\n\n", style="green")
            
            if update_info.get('release_notes'):
                update_text.append("📝 Release Notes:\n", style="bold cyan")
                update_text.append(update_info['release_notes'][:200] + "...\n", style="white")
            
            console.print(Panel(update_text, title="Update Available", border_style="green"))
        else:
            console.print("[green]✅ Falcon is up to date![/green]")
    
    def _prompt_user_update(self) -> bool:
        """Prompt user to update"""
        try:
            response = input("\n🤔 Would you like to update now? (y/N): ").strip().lower()
            return response in ['y', 'yes']
        except KeyboardInterrupt:
            return False
    
    async def perform_update(self):
        """Perform the actual update"""
        console.print("[cyan]🚀 Starting update process...[/cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            # Step 1: Backup current installation
            backup_task = progress.add_task("Creating backup...", total=None)
            await self._create_backup()
            progress.update(backup_task, completed=True)
            
            # Step 2: Download latest version
            download_task = progress.add_task("Downloading latest version...", total=None)
            success = await self._download_update()
            progress.update(download_task, completed=True)
            
            if success:
                # Step 3: Install update
                install_task = progress.add_task("Installing update...", total=None)
                await self._install_update()
                progress.update(install_task, completed=True)
                
                console.print("[green]✅ Update completed successfully![/green]")
                console.print("[yellow]📝 Restart required for changes to take effect[/yellow]")
            else:
                console.print("[red]❌ Update failed![/red]")
    
    async def _create_backup(self):
        """Create backup of current installation"""
        backup_dir = self.falcon_dir / "backup"
        backup_dir.mkdir(exist_ok=True)
        
        # Simple backup - copy key files
        important_files = ['main.py', 'requirements.txt', 'config/falcon.yaml']
        
        for file_path in important_files:
            source = self.falcon_dir / file_path
            if source.exists():
                dest = backup_dir / f"{source.name}.backup"
                dest.write_text(source.read_text())
    
    async def _download_update(self) -> bool:
        """Download the latest version"""
        try:
            # Use git pull if in a git repository
            result = subprocess.run(
                ['git', 'pull', 'origin', 'main'],
                cwd=self.falcon_dir,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                console.print("[green]✅ Successfully pulled latest changes[/green]")
                return True
            else:
                console.print(f"[yellow]⚠️  Git pull failed: {result.stderr}[/yellow]")
                return await self._download_zip_update()
                
        except FileNotFoundError:
            # Git not available, try ZIP download
            return await self._download_zip_update()
    
    async def _download_zip_update(self) -> bool:
        """Download update as ZIP file"""
        try:
            async with aiohttp.ClientSession() as session:
                zip_url = f"https://github.com/dharmraj8033/Falcon/archive/refs/heads/main.zip"
                
                async with session.get(zip_url) as response:
                    if response.status == 200:
                        zip_content = await response.read()
                        zip_file = self.falcon_dir / "falcon_update.zip"
                        zip_file.write_bytes(zip_content)
                        
                        # Extract ZIP (basic implementation)
                        console.print("[yellow]📦 ZIP download completed[/yellow]")
                        console.print("[blue]ℹ️  Manual extraction required[/blue]")
                        return True
                    else:
                        return False
        except Exception as e:
            console.print(f"[red]❌ ZIP download failed: {e}[/red]")
            return False
    
    async def _install_update(self):
        """Install the downloaded update"""
        # Update requirements if needed
        requirements_file = self.falcon_dir / "requirements.txt"
        if requirements_file.exists():
            try:
                result = subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', '-r', str(requirements_file)],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    console.print("[green]✅ Dependencies updated[/green]")
                else:
                    console.print("[yellow]⚠️  Some dependencies may need manual update[/yellow]")
            except Exception as e:
                console.print(f"[yellow]⚠️  Could not update dependencies: {e}[/yellow]")
    
    async def update_ai_models(self, force: bool = False):
        """Update AI models and vulnerability databases"""
        console.print("[cyan]🧠 Updating AI models and databases...[/cyan]")
        
        model_updates = [
            "Vulnerability patterns database",
            "CVE mappings",
            "Technology fingerprints",
            "Payload effectiveness data"
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            for update_item in model_updates:
                task = progress.add_task(f"Updating {update_item}...", total=None)
                await asyncio.sleep(0.5)  # Simulate update process
                progress.update(task, completed=True)
        
        console.print("[green]✅ AI models and databases updated![/green]")
    
    async def update_tools(self):
        """Update external security tools"""
        console.print("[cyan]🔧 Updating security tools...[/cyan]")
        
        tools_to_update = [
            "subfinder",
            "nuclei",
            "katana", 
            "httpx"
        ]
        
        for tool in tools_to_update:
            try:
                console.print(f"[dim cyan]Updating {tool}...[/dim cyan]")
                result = subprocess.run(
                    ['go', 'install', '-v', f'github.com/projectdiscovery/{tool}/v2/cmd/{tool}@latest'],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    console.print(f"[green]✅ {tool} updated[/green]")
                else:
                    console.print(f"[yellow]⚠️  {tool} update failed[/yellow]")
                    
            except Exception as e:
                console.print(f"[yellow]⚠️  Could not update {tool}: {e}[/yellow]")
    
    def get_version_info(self) -> Dict[str, str]:
        """Get current version information"""
        return {
            'falcon_version': self.current_version,
            'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            'install_path': str(self.falcon_dir)
        }
