"""
Falcon Banner and Visual Elements
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box
import random

console = Console()

FALCON_ASCII = """
    ███████╗ █████╗ ██╗      ██████╗ ██████╗ ███╗   ██╗
    ██╔════╝██╔══██╗██║     ██╔════╝██╔═══██╗████╗  ██║
    █████╗  ███████║██║     ██║     ██║   ██║██╔██╗ ██║
    ██╔══╝  ██╔══██║██║     ██║     ██║   ██║██║╚██╗██║
    ██║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                🦅 AI-Enhanced Vulnerability Scanner
"""

MOTIVATIONAL_QUOTES = [
    "🎯 Hunt vulnerabilities like a falcon hunts prey",
    "🧠 AI-powered scanning for the modern security researcher", 
    "⚡ Speed, intelligence, and precision in one tool",
    "🔍 Seeing what others miss with artificial intelligence",
    "🛡️ Protecting the digital world, one scan at a time",
    "🚀 Next-generation security testing at your fingertips"
]

def show_banner():
    """Display the Falcon banner with random motivational quote"""
    quote = random.choice(MOTIVATIONAL_QUOTES)
    
    banner_text = Text()
    banner_text.append(FALCON_ASCII, style="bold red")
    banner_text.append(f"\n{quote}", style="italic cyan")
    banner_text.append(f"\nVersion 1.0.0 | Made with ❤️ by Falcon Security Team", style="dim white")
    
    panel = Panel(
        banner_text,
        box=box.DOUBLE,
        border_style="red",
        padding=(1, 2)
    )
    
    console.print(panel)
    console.print()

def show_scan_header(target: str, scan_type: str):
    """Show scan header with target information"""
    header = Text()
    header.append("🎯 Target: ", style="bold cyan")
    header.append(target, style="bold white")
    header.append(f"\n📋 Scan Type: ", style="bold cyan") 
    header.append(scan_type, style="bold yellow")
    
    console.print(Panel(header, title="Scan Information", border_style="cyan"))

def show_progress_info(message: str, style: str = "cyan"):
    """Show progress information"""
    console.print(f"[{style}]ℹ️  {message}[/{style}]")

def show_success(message: str):
    """Show success message"""
    console.print(f"[green]✅ {message}[/green]")

def show_warning(message: str):
    """Show warning message"""
    console.print(f"[yellow]⚠️  {message}[/yellow]")

def show_error(message: str):
    """Show error message"""
    console.print(f"[red]❌ {message}[/red]")

def show_vulnerability(vuln_data: dict):
    """Display vulnerability information"""
    severity_colors = {
        'CRITICAL': 'bold red',
        'HIGH': 'red',
        'MEDIUM': 'yellow',
        'LOW': 'blue',
        'INFO': 'cyan'
    }
    
    severity = vuln_data.get('severity', 'INFO').upper()
    color = severity_colors.get(severity, 'white')
    
    vuln_text = Text()
    vuln_text.append(f"🚨 {vuln_data.get('name', 'Unknown Vulnerability')}", style=f"bold {color}")
    vuln_text.append(f"\n📍 URL: {vuln_data.get('url', 'N/A')}", style="white")
    vuln_text.append(f"\n⚠️  Severity: {severity}", style=color)
    vuln_text.append(f"\n📝 Description: {vuln_data.get('description', 'No description')}", style="dim white")
    
    if vuln_data.get('ai_explanation'):
        vuln_text.append(f"\n🧠 AI Analysis: {vuln_data['ai_explanation']}", style="italic cyan")
    
    console.print(Panel(vuln_text, title="Vulnerability Found", border_style=color))

def show_tech_stack(tech_data: dict):
    """Display detected technology stack"""
    tech_text = Text()
    tech_text.append("🔧 Detected Technologies:\n", style="bold cyan")
    
    for category, technologies in tech_data.items():
        tech_text.append(f"\n📂 {category.title()}:", style="bold yellow")
        for tech in technologies:
            version = tech.get('version', 'Unknown')
            confidence = tech.get('confidence', 0) * 100
            tech_text.append(f"\n  • {tech['name']} ({version}) - {confidence:.1f}%", style="white")
    
    console.print(Panel(tech_text, title="Technology Detection", border_style="cyan"))

def show_stats(stats: dict):
    """Display scan statistics"""
    stats_text = Text()
    stats_text.append("📊 Scan Statistics\n", style="bold cyan")
    
    for key, value in stats.items():
        stats_text.append(f"{key}: ", style="cyan")
        stats_text.append(f"{value}\n", style="white")
    
    console.print(Panel(stats_text, title="Results Summary", border_style="green"))
