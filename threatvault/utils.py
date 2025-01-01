import sys

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def print_banner():
    banner = f"""{Colors.CYAN}{Colors.BOLD}
   ______          ________             _  __
  / ____/___  ____/ /__  /___  ___     | |/ /
 / /   / __ \/ __  /  / // _ \/ _ \____ |   / 
/ /___/ /_/ / /_/ /  / //  __/  __/___//   |  
\____/\____/\__,_/  /____/\___/\___/  /_/|_|  
         ThreatVault Enterprise Framework v2.4.0
         CodZeeX Cyber Intelligence | RobsHs
{Colors.RESET}"""
    print(banner)

def log_info(msg):
    print(f"[{Colors.BLUE}+{Colors.RESET}] {msg}")

def log_success(msg):
    print(f"[{Colors.GREEN}OK{Colors.RESET}] {msg}")

def log_warn(msg):
    print(f"[{Colors.YELLOW}!{Colors.RESET}] {msg}")

def log_alert(msg):
    print(f"[{Colors.RED}ALERT{Colors.RESET}] {msg}")
