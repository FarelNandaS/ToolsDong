import time
import socket
import urllib.request
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from utils import clear_screen

console = Console()

def gether_domain_info(domain: str):
    clear_screen()

    console.print(f"\n[bold green]🔍 Mengumpulkan Informasi Untuk:[/bold green] [bold yellow]{domain}[/bold yellow]")

    domain = domain.replace("https://", "").replace("http://", "").strip("/")

    try:
        ip_address = socket.gethostbyname(domain)
        console.print(f"[bold green][+][/bold green] IP Address: [bold white]{ip_address}[/bold white]")
    except socket.gaierror:
        console.print("[bold red][!] Gagal menyelesaikan resolusi nama domain.[/bold red]")
        return

    try:
        url = f"https://{domain}"
        req = urllib.request.Request(url, headers={'User-agent': 'ToolsDong-Recon/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            headers = response.info()

            table = Table(title=f"HTTP Response Headers - {domain}", expand=True)
            table.add_column("Header Name", style='bold green')
            table.add_column("Value", style='bold green')

            for key, value in headers.items():
                table.add_row(key, value)

            console.print(table)
    except Exception as e:
        console.print(f"[bold red][!] Gagal mengambil HTTP Headers: {e}[/bold red]")

def run():
    while True:
        try:
            clear_screen()

            console.print("[bold green]Information Gethering[/bold green]")
            console.print("[bold yellow]Tekan Ctrl+C untuk kembali ke menu utama ToolsDong...[/bold yellow]")
            domain = console.input("[bold yellow]Masukan domain: [/bold yellow]")

            if not domain:
                continue

            gether_domain_info(domain)
            Prompt.ask("Tekan Enter untuk kembali...")
        except KeyboardInterrupt:
            console.print("\n[bold yellow][!] Keluar Dari Information Gethering... Kembali ke Menu Utama.[/bold yellow]")
            time.sleep(1)
            break