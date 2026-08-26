import socket
import time
import re
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

from utils import clear_screen

console = Console()

def is_valid_ip(target: str) -> bool:
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False

def tracking(target):
    clear_screen()
    cleaned_target = target.replace("https://", "").replace("http://", "").strip()
    cleaned_target = cleaned_target.split('/')[0].split('?')[0].split('#')[0]

    if not cleaned_target:
        console.print("[bold red][!] Error: Input tidak boleh kosong.[/bold red]")

    try:
        if is_valid_ip(cleaned_target):
            ip_address = cleaned_target
            display_host = cleaned_target
        else:
            with console.status(f"[bold green]Melakukan DNS lookup untuk {cleaned_target}...[/bold green]", spinner="dots"):
                ip_address = socket.gethostbyname(cleaned_target)
            display_host = f"{cleaned_target} ({ip_address})"

        with console.status(f"[bold green]Mengambil data lokasi IP {ip_address}...[/bold green]", spinner="dots"):
            api_url = f"http://ip-api.com/json/{ip_address}"
            response = requests.get(api_url, timeout=5).json()

        if response.get("status") == "success":
            table = Table(show_header=False, box=None)
            table.add_column("Property", style="bold green", width=20)
            table.add_column("Value", style="bold white")

            table.add_row("Target Input", target)
            table.add_row("Resolved Host", display_host)
            table.add_row("IP Address", ip_address)
            table.add_row("Negara", f"{response.get('country')} ({response.get('countyCode')})")
            table.add_row("Wilayah/Provinsi", response.get('regionName'))
            table.add_row("Kota", response.get('city'))
            table.add_row("Kode Pos", str(response.get('zip', 'N/A')))
            table.add_row("ISP", response.get('isp'))
            table.add_row("Organisasi", response.get('org', 'N/A'))
            table.add_row("Koordinasi", f"Lat: {response.get('lat')}, Lon: {response.get('lon')}")
            table.add_row("Timezone", response.get('timezone'))

            console.print(Panel(table, title="[bold green]📍 IP Geolocation Report[/bold green]", border_style="bright_blue", padding=(1, 2), expand=False))
        else:
            message = response.get('message', 'Gagal mengambil data lokasi.')
            console.print(f"[bold red][!] Gagal: {message}[/bold red]")
    except socket.gaierror:
        console.print(f"[bold red][!] Error: Host/Domain '[yellow]{cleaned_target}[/yellow]' tidak valid atau tidak ditemukan[/bold red]")
    except requests.RequestException as e:
        console.print(f"[bold red][!] Error Koneksi API: {e}[/bold e]")
    except Exception as e:
        console.print(f"[bold red][!] Terjadi Kesalahan: {e}[/bold e]")

def run():
    while True:
        try:
            clear_screen()
            console.print("[bold green]=== Traking Geolocation ===[/bold green]")
            console.print("[bold yellow]Tekan Ctrl+C untuk kembali ke menu utama ToolsDong...[/bold yellow]")
            target = console.input("[bold yellow]Masukan URL, Domain, Atau IP: [/bold yellow]")

            tracking(target)
            Prompt.ask("Tekan Enter Untuk Kembali...")
        except KeyboardInterrupt:
            console.print("\n[bold yellow][!] Keluar Dari Traking Geolocation... Kembali ke Menu Utama.[/bold yellow]")
            time.sleep(1)
            break