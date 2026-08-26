import os
import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from utils import clear_screen
from tools import sysmon, vuln_scan, wifi_tools, info_gether, tracking_geo

console = Console()

LOGO_ART = r"""[bold green]
█▀█▀█ █▀█ █▀█ █   █▀▀ █▀▄ █▀█ █▄ █ █▀▀
  █   █ █ █ █ █   ▀▀█ █ █ █ █ █ ▀█ █ █
  ▀   ▀▀▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀▀  ▀▀▀ ▀  ▀ ▀▀▀
[/bold green]"""

def flush_input_buffer():
    try:
        if os.name == 'nt':  # Windows
            import msvcrt
            while msvcrt.kbhit():
                msvcrt.getch()
        else:  # Linux / macOS
            import termios
            import sys
            termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception:
        pass

def exit_app():
    clear_screen()
    console.print("[bold green]Terima kasih telah menggunakan ToolsDong![/bold green]")
    sys.exit(0)

def main():
    try:
        while True:
            clear_screen()

            console.print(LOGO_ART)
            
            menu_text = (
                "[bold cyan]1. System Resource Monitor[/bold cyan]\n"
                "[bold cyan]2. Wi-Fi Scanner & Password Manager[/bold cyan]\n"
                "[bold cyan]3. Information Gethering[/bold cyan]\n"
                "[bold cyan]4. Vulnerable Scanner[/bold cyan]\n"
                "[bold cyan]5. Traking Geolocation[/bold cyan]\n"
                "[bold red]0. Keluar[/bold red]"
            )
            console.print(Panel(menu_text, title="[bold green]MAIN MENU[/bold green]", expand=False))

            flush_input_buffer()
            
            pilihan = Prompt.ask("Pilih menu")
            
            if pilihan == "1":
                sysmon.run()
            elif pilihan == "2":
                wifi_tools.run()
            elif pilihan == "3":
                info_gether.run()
            elif pilihan == "4":
                vuln_scan.run()
            elif pilihan == "5":
                tracking_geo.run()
            elif pilihan in ["0"]:
                exit_app()
            else :
                console.print("\n[bold red]Kode yang anda masukan salah")
                time.sleep(1)
    except KeyboardInterrupt:
        exit_app()

if __name__ == "__main__":
    main()