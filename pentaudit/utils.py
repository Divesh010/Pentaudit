"""
utils.py — Shared helper functions used across all modules
===========================================================

WHY THIS FILE EXISTS:
Functions that multiple modules need (like printing colored output,
formatting results, or timing operations) go here so we don't 
repeat code. This is called the "DRY principle" — Don't Repeat Yourself.
"""

import time
import datetime
from rich.console import Console
from rich.table import Table
import sys
from rich.panel import Panel
from rich import box

# Rich console for beautiful terminal output
console = Console()


def _safe_print(text, *args, **kwargs):
    """
    Prints to the console, catching UnicodeEncodeError and falling back to ASCII.
    """
    try:
        console.print(text, *args, **kwargs)
    except UnicodeEncodeError:
        try:
            if isinstance(text, str):
                # Clean up known non-encodable characters using safe raw unicode escapes
                clean = text
                for char, replacement in [
                    ("\u25b6", ">>>"), ("\u2713", "[+]"), ("\u26a0", "[!]"), 
                    ("\u2717", "[-]") , ("\u2139", "[*]"), ("\u2192", "->"),
                    ("\u2554", "+"), ("\u2550", "-"), ("\u2557", "+"),
                    ("\u2551", "|"), ("\u255a", "+"), ("\u255d", "+")
                ]:
                    clean = clean.replace(char, replacement)
                # Encode with replace just in case other characters remain
                clean_text = clean.encode("ascii", errors="replace").decode("ascii")
                console.print(clean_text, *args, **kwargs)
            else:
                # If it's a Table, change the box to ASCII
                if hasattr(text, "box"):
                    text.box = box.ASCII
                console.print(text, *args, **kwargs)
        except Exception:
            # Absolute fallback to standard print as a last resort
            try:
                clean = str(text)
                for char, replacement in [
                    ("\u25b6", ">>>"), ("\u2713", "[+]"), ("\u26a0", "[!]"), 
                    ("\u2717", "[-]") , ("\u2139", "[*]"), ("\u2192", "->"),
                    ("\u2554", "+"), ("\u2550", "-"), ("\u2557", "+"),
                    ("\u2551", "|"), ("\u255a", "+"), ("\u255d", "+")
                ]:
                    clean = clean.replace(char, replacement)
                print(clean.encode("ascii", errors="replace").decode("ascii"))
            except Exception:
                pass


# Detect if the console encoding supports Unicode box characters and symbols using safe escapes
try:
    "\u2554\u2550\u2588\u2588\u2588\u25b6\u2713\u26a0\u2717\u2139\u2192".encode(console.encoding or "ascii")
    UNICODE_SUPPORT = True
except (UnicodeEncodeError, TypeError):
    UNICODE_SUPPORT = False

# Character definitions with ASCII fallbacks using escapes
CHAR_PHASE = "\u25b6" if UNICODE_SUPPORT else ">>>"
CHAR_SUCCESS = "\u2713" if UNICODE_SUPPORT else "[+]"
CHAR_WARNING = "\u26a0" if UNICODE_SUPPORT else "[!]"
CHAR_ERROR = "\u2717" if UNICODE_SUPPORT else "[-]"
CHAR_INFO = "\u2139" if UNICODE_SUPPORT else "[*]"




def print_banner():
    """Print the PentAudit tool banner when the program starts."""
    if UNICODE_SUPPORT:
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ███████╗███╗   ██╗████████╗ █████╗ ██╗   ██╗██████╗║
║   ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██║   ██║██╔══██║
║   ██████╔╝█████╗  ██╔██╗ ██║   ██║   ███████║██║   ██║██║  ██║
║   ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██║██║   ██║██║  ██║
║   ██║     ███████╗██║ ╚████║   ██║   ██║  ██║╚██████╔╝██████╔║
║   ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═════╝║
║                                                               ║
║   Autonomous Pentest Platform Security Auditor    v1.0.0      ║
║   Author: Divesh Gupta                                       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    else:
        banner = """
+---------------------------------------------------------------+
|                                                               |
|   ██████╗ ███████╗███╗   ██╗████████╗ █████╗ ██╗   ██╗██████╗ |
|   ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██║   ██║██╔══██║ |
|   ██████╔╝█████╗  ██╔██╗ ██║   ██║   ███████║██║   ██║██║  ██║ |
|   ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██║██║   ██║██║  ██║ |
|   ██║     ███████╗██║ ╚████║   ██║   ██║  ██║╚██████╔╝██████╔║ |
|   ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═════╝ |
|                                                               |
|   Autonomous Pentest Platform Security Auditor    v1.0.0      |
|   Author: Divesh Gupta                                        |
|                                                               |
+---------------------------------------------------------------+
"""
    # Replace block character approximations for ASCII banner if needed
    if not UNICODE_SUPPORT:
        banner = banner.replace("██████╗", "PENTAUDIT").replace("███████╗", "").replace("███╗", "").replace("██╗", "").replace("██╔══██╗", "").replace("██╔════╝", "").replace("████╗", "").replace("██║", "").replace("╚══██╔══╝", "").replace("██╔══██╗", "").replace("██╔██╗", "").replace("███████║", "").replace("██╔═══╝", "").replace("██╔══╝", "").replace("╚██╗", "").replace("██║ ╚████║", "").replace("╚██████╔╝", "").replace("██████╔", "").replace("╚═╝", "").replace("╚══════╝", "").replace("╚═══╝", "").replace("╚═════╝", "").replace("╚═════╝", "")
        banner = """
+---------------------------------------------------------------+
|   PENTAUDIT - Autonomous Pentest Platform Security Auditor    |
|   Version 1.0.0 | Author: Divesh Gupta                        |
+---------------------------------------------------------------+
"""
    _safe_print(banner, style="bold cyan")


def print_phase(phase_name):
    """Print a phase header to show progress."""
    _safe_print(f"\n{'='*60}", style="dim")
    _safe_print(f"  {CHAR_PHASE} {phase_name}", style="bold yellow")
    _safe_print(f"{'='*60}", style="dim")


def print_finding(check_id, title, risk_level, details=""):
    """Print a finding with color-coded risk level."""
    colors = {
        "CRITICAL": "bold red",
        "HIGH": "bold bright_red",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
        "INFO": "bold cyan",
    }
    style = colors.get(risk_level, "white")
    _safe_print(f"\n  [{risk_level}] {check_id}: {title}", style=style)
    if details:
        _safe_print(f"         {details}", style="dim")


def print_success(message):
    """Print a success message."""
    _safe_print(f"  {CHAR_SUCCESS} {message}", style="bold green")


def print_warning(message):
    """Print a warning message."""
    _safe_print(f"  {CHAR_WARNING} {message}", style="bold yellow")


def print_error(message):
    """Print an error message."""
    _safe_print(f"  {CHAR_ERROR} {message}", style="bold red")


def print_info(message):
    """Print an info message."""
    _safe_print(f"  {CHAR_INFO} {message}", style="bold cyan")



def timestamp():
    """Return current timestamp in ISO format."""
    return datetime.datetime.now().isoformat()


def timer_start():
    """Start a timer. Returns the start time."""
    return time.time()


def timer_end(start_time):
    """End a timer. Returns elapsed seconds."""
    return round(time.time() - start_time, 2)


def display_results_table(results, title="Scan Results"):
    """
    Display results as a beautiful table in the terminal.
    
    'results' is a list of dicts, each with keys like:
    - host, port, platform, status, risk_level, etc.
    """
    if not results:
        print_warning("No results to display.")
        return

    table = Table(title=title, box=box.ROUNDED, show_lines=True)
    
    # Add columns based on the keys in the first result
    columns_added = False
    for result in results:
        if not columns_added:
            for key in result.keys():
                table.add_column(
                    key.replace("_", " ").title(),
                    style="cyan" if key != "risk_level" else "bold",
                )
            columns_added = True
        
        # Color-code risk level
        row_values = []
        for key, value in result.items():
            if key == "risk_level":
                colors = {"CRITICAL": "red", "HIGH": "bright_red", 
                         "MEDIUM": "yellow", "LOW": "green", "INFO": "cyan"}
                row_values.append(f"[{colors.get(value, 'white')}]{value}[/]")
            else:
                row_values.append(str(value))
        table.add_row(*row_values)
    
    _safe_print(table)
