from __future__ import annotations
import os
import platform

try:
    # Couleurs cross-platform (Windows ok)
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except Exception:
    # Fallback sans couleurs si colorama non dispo
    class _Dummy:
        RESET_ALL = ""
    class _Fore(_Dummy):
        CYAN = GREEN = MAGENTA = YELLOW = RED = BLUE = WHITE = ""
    class _Style(_Dummy):
        BRIGHT = NORMAL = DIM = ""
    Fore, Style = _Fore(), _Style()


COREIDS_ASCII = r"""
 __   _______ _____   _____ 
 \ \ / /_   _|  __ \ / ____|
  \ V /  | | | |  | | (___  
   > <   | | | |  | |\___ \ 
  / . \ _| |_| |__| |____) |
 /_/ \_\_____|_____/|_____/ 
"""

SLOGAN = "See the threat. Stop the breach."


def print_banner() -> None:
    print(Fore.CYAN + Style.BRIGHT + COREIDS_ASCII + Style.RESET_ALL)
    print(Fore.MAGENTA + Style.BRIGHT + "XIDS" + Style.RESET_ALL + " — " +
          Fore.YELLOW + SLOGAN + Style.RESET_ALL)
    print(Fore.BLUE + f"OS: {platform.system()} {platform.release()}   " +
          Fore.BLUE + f"User: {os.getenv('USERNAME') or os.getenv('USER') or 'unknown'}" + Style.RESET_ALL)
    print(Fore.WHITE + "-" * 72 + Style.RESET_ALL)
