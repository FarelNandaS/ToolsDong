import time
import psutil
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout

from utils import clear_screen

def build_system_table() -> Table:
    cpu_usage = psutil.cpu_percent(interval=None)
    cpu_count = psutil.cpu_count(logical=True)

    ram = psutil.virtual_memory()
    ram_total_gb = ram.total / (1024 ** 3)
    ram_used_gb = ram.used / (1024 ** 3)

    disk = psutil.disk_usage('/')
    disk_total_gb = disk.total / (1024 ** 3)
    disk_used_gb = disk.used / (1024 ** 3)

    table = Table(title="[bold green]System Resource Monitor[/bold green]", expand=True)
    table.add_column("Komponen", style="bold white", width=15)
    table.add_column("Penggunaan", style="cyan")
    table.add_column("Detail", style="magenta")

    cpu_color = "red" if cpu_usage > 80 else ("yellow" if cpu_usage > 50 else "green")
    table.add_row(
        "CPU",
        f"[{cpu_color}]{cpu_usage:.1f}%[/{cpu_color}]",
        f"{cpu_count} Threads / Cores"
    )

    ram_color = "red" if ram.percent > 80 else ("yellow" if ram.percent > 50 else "green")
    table.add_row(
        "RAM",
        f"[{ram_color}]{ram.percent:.1f}%[/{ram_color}]",
        f"{ram_used_gb:.2f} GB / {ram_total_gb:.2f} GB"
    )

    disk_color = "red" if disk.percent > 80 else ("yellow" if disk.percent > 50 else "green")
    table.add_row(
        "Disk (/)",
        f"[{disk_color}]{disk.percent:.1f}%[/{disk_color}]",
        f"{disk_used_gb:.2f} GB / {disk_total_gb:.2f} GB"
    )

    return table


def build_processes_table(limit: int = 10) -> Table:
    proc_table = Table(title=f"[bold blue]Top {limit} Proses (Penggunaan RAM)[/bold blue]", expand=True)
    proc_table.add_column("PID", style="dim", width=8)
    proc_table.add_column("Nama", style="bold cyan")
    proc_table.add_column("RAM (%)", justify="right", style="yellow")
    proc_table.add_column("CPU (%)", justify="right", style="green")

    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    top_processes = sorted(processes, key=lambda x: x['memory_percent'] or 0, reverse=True)[:limit]

    for p in top_processes:
        proc_table.add_row(
            str(p['pid']),
            p['name'] or "N/A",
            f"{p['memory_percent']:.1f}%" if p['memory_percent'] else "0.0%",
            f"{p['cpu_percent']:.1f}%" if p['cpu_percent'] else "0.0%"
        )

    return proc_table


def make_layout() -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=10),
        Layout(name="processes"),
        Layout(name="footer", size=3)
    )
    layout["header"].update(Panel(build_system_table(), border_style="bright_blue"))
    layout["processes"].update(Panel(build_processes_table(), border_style="bright_magenta"))

    footer_text = "[bold yellow]Petunjuk:[/bold yellow] Tekan [bold red]Ctrl + C[/bold red] untuk menghentikan monitor dan kembali ke menu utama ToolsDong."
    layout["footer"].update(Panel(footer_text, border_style="dim white"))
    return layout


def run():
    console = Console()
    psutil.cpu_percent(interval=None)
    clear_screen()
    
    console.print("[bold green]System Resource Monitor Aktif.[/bold green]")
    console.print("[yellow]Tekan Ctrl+C untuk menghentikan monitor dan kembali ke Menu Utama ToolsDong...[/yellow]\n")
    
    time.sleep(1)
    
    try:
        with Live(make_layout(), refresh_per_second=1, screen=True) as live:
            while True:
                time.sleep(1)
                live.update(make_layout())
    except KeyboardInterrupt:
        clear_screen()
        console.print("[bold yellow][!] Keluar Dari System Resource Monitor... Kembali ke Menu Utama.[/bold yellow]")
        time.sleep(1)