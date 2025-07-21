"""
CLI Banner and Visual Elements
"""

import random

# Try to import colorama, fallback to basic colors if not available
try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    # Fallback color codes for systems without colorama
    class Fore:
        CYAN = '\033[96m'
        YELLOW = '\033[93m'
        GREEN = '\033[92m'
        WHITE = '\033[97m'
        MAGENTA = '\033[95m'
        RED = '\033[91m'
        BLUE = '\033[94m'
        LIGHTBLACK_EX = '\033[90m'
    
    class Back:
        WHITE = '\033[107m'
    
    class Style:
        RESET_ALL = '\033[0m'
    
    COLORAMA_AVAILABLE = False

FALCON_ASCII = """
    ███████╗ █████╗ ██╗      ██████╗ ██████╗ ███╗   ██╗    █████╗ ██╗
    ██╔════╝██╔══██╗██║     ██╔════╝██╔═══██╗████╗  ██║   ██╔══██╗██║
    █████╗  ███████║██║     ██║     ██║   ██║██╔██╗ ██║   ███████║██║
    ██╔══╝  ██╔══██║██║     ██║     ██║   ██║██║╚██╗██║   ██╔══██║██║
    ██║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╗██║  ██║██║
    ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝
"""

TAGLINES = [
    "🦅 Soar above the vulnerabilities",
    "🎯 AI-powered precision hunting",
    "🔍 Intelligence-driven security scanning",
    "⚡ Faster, smarter, deadlier",
    "🧠 Where AI meets cybersecurity",
]

def print_banner():
    """Print the Falcon banner with random tagline"""
    print(Fore.CYAN + FALCON_ASCII)
    print(Fore.YELLOW + "    " + "─" * 60)
    print(Fore.GREEN + f"    {random.choice(TAGLINES)}")
    print(Fore.YELLOW + "    " + "─" * 60)
    print(Fore.WHITE + f"    Version: 1.0.0 | AI-Enhanced Vulnerability Scanner")
    print(Fore.MAGENTA + f"    Author: Falcon Security Team | github.com/falcon-security")
    print()

def print_section_header(title, color=Fore.CYAN):
    """Print a styled section header"""
    print(f"\n{color}{'='*60}")
    print(f"{color}  {title}")
    print(f"{color}{'='*60}")

def print_vulnerability(vuln_type, severity, url, description=""):
    """Print a formatted vulnerability finding"""
    severity_colors = {
        'CRITICAL': Fore.RED + Back.WHITE,
        'HIGH': Fore.RED,
        'MEDIUM': Fore.YELLOW,
        'LOW': Fore.GREEN,
        'INFO': Fore.BLUE
    }
    
    severity_color = severity_colors.get(severity.upper(), Fore.WHITE)
    
    print(f"{severity_color}[{severity.upper()}]{Style.RESET_ALL} ", end="")
    print(f"{Fore.CYAN}{vuln_type}{Style.RESET_ALL} ", end="")
    print(f"found at {Fore.WHITE}{url}{Style.RESET_ALL}")
    
    if description:
        print(f"    {Fore.LIGHTBLACK_EX}└─ {description}{Style.RESET_ALL}")

def print_tech_stack(tech_info):
    """Print detected technology stack"""
    print(f"\n{Fore.CYAN}🔧 Technology Stack Detected:")
    for category, items in tech_info.items():
        if items:
            print(f"  {Fore.YELLOW}{category}:")
            for item in items:
                version = item.get('version', 'Unknown')
                confidence = item.get('confidence', 'Unknown')
                print(f"    {Fore.GREEN}└─ {item['name']} {version} (Confidence: {confidence}%)")

def print_scan_summary(stats):
    """Print scan summary statistics"""
    print(f"\n{Fore.CYAN}📊 Scan Summary:")
    print(f"  {Fore.WHITE}Total URLs Scanned: {Fore.GREEN}{stats.get('urls_scanned', 0)}")
    print(f"  {Fore.WHITE}Vulnerabilities Found: {Fore.RED}{stats.get('vulnerabilities', 0)}")
    print(f"  {Fore.WHITE}Parameters Discovered: {Fore.YELLOW}{stats.get('parameters', 0)}")
    print(f"  {Fore.WHITE}Subdomains Found: {Fore.BLUE}{stats.get('subdomains', 0)}")
    print(f"  {Fore.WHITE}Scan Duration: {Fore.MAGENTA}{stats.get('duration', '0s')}")
    
def print_progress_bar(current, total, prefix="Progress", suffix="Complete", length=50):
    """Print a progress bar"""
    percent = ("{0:.1f}").format(100 * (current / float(total)))
    filled_length = int(length * current // total)
    bar = '█' * filled_length + '-' * (length - filled_length)
    print(f'\r{Fore.CYAN}{prefix} |{bar}| {percent}% {suffix}', end='\r')
    if current == total:
        print()

def print_ai_insight(insight_type, message, confidence=None):
    """Print AI-generated insights"""
    icons = {
        'recommendation': '💡',
        'warning': '⚠️',
        'analysis': '🧠',
        'prediction': '🔮'
    }
    
    icon = icons.get(insight_type, '🤖')
    print(f"\n{Fore.MAGENTA}{icon} AI Insight ({insight_type.title()}):")
    print(f"  {Fore.WHITE}{message}")
    
    if confidence:
        color = Fore.GREEN if confidence > 80 else Fore.YELLOW if confidence > 60 else Fore.RED
        print(f"  {Fore.LIGHTBLACK_EX}Confidence: {color}{confidence}%{Style.RESET_ALL}")

def print_error(message):
    """Print an error message"""
    print(f"{Fore.RED}❌ Error: {message}{Style.RESET_ALL}")

def print_warning(message):
    """Print a warning message"""
    print(f"{Fore.YELLOW}⚠️  Warning: {message}{Style.RESET_ALL}")

def print_info(message):
    """Print an info message"""
    print(f"{Fore.BLUE}ℹ️  Info: {message}{Style.RESET_ALL}")

def print_success(message):
    """Print a success message"""
    print(f"{Fore.GREEN}✅ Success: {message}{Style.RESET_ALL}")
