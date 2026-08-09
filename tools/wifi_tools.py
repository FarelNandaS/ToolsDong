import os
import sys
import re
import subprocess
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.progress_bar import ProgressBar

console = Console()

def flush_input():
    try:
        if os.name == "nt" :
            import msvcrt
            while msvcrt.kbhit():
                msvcrt.getch()
        else :
            import termios
            terios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception:
        pass

def get_signal_bar(signal_percent: int) -> str :
    return ProgressBar(
        total=100,
        completed=signal_percent,
        width=12 # Lebar indikator bar di dalam tabel
    )

def scan_nearby_wifi_windows():
    networks = []
    try:
        # Tambahkan timeout 5 detik agar tidak menggantung/stuck selamanya
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            encoding="utf-8",
            errors="ignore",
            timeout=5
        )

        current_ssid = "Hidden / Unknown"
        current_auth = "Unknown"
        
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # Deteksi SSID Baru
            if line.startswith("SSID "):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_ssid = parts[1].strip()
                    if not current_ssid:
                        current_ssid = "[Hidden SSID]"
                        
            elif line.startswith("Authentication") or line.startswith("Autentikasi"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_auth = parts[1].strip()

            # Deteksi Setiap BSSID (Access Point)
            elif line.startswith("BSSID "):
                bssid_mac = line.split(":", 1)[1].strip() if ":" in line else "N/A"
                signal = 0
                channel = "N/A"
                radio = "N/A"

                # Baca detail BSSID di baris-baris berikutnya
                j = i + 1
                while j < len(lines) and not lines[j].startswith("BSSID ") and not lines[j].startswith("SSID "):
                    sub_line = lines[j]
                    if sub_line.startswith("Signal") or sub_line.startswith("Sinyal"):
                        sig_str = sub_line.split(":", 1)[1].replace("%", "").strip()
                        signal = int(sig_str) if sig_str.isdigit() else 0
                    elif sub_line.startswith("Channel") or sub_line.startswith("Saluran"):
                        channel = sub_line.split(":", 1)[1].strip()
                    elif sub_line.startswith("Radio type") or sub_line.startswith("Tipe radio"):
                        radio = sub_line.split(":", 1)[1].strip()
                    j += 1

                networks.append({
                    "ssid": str(current_ssid),
                    "bssid": str(bssid_mac),
                    "signal": signal,
                    "channel": str(channel),
                    "auth": str(current_auth),
                    "radio": str(radio)
                })
                i = j - 1
            i += 1

    except subprocess.TimeoutExpired:
        console.print("[bold yellow]Pemindaian Wi-Fi melebihi batas waktu (Timeout 5s). Memuat hasil parsial...[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]Gagal memindai Wi-Fi: {e}[/bold red]")

    return sorted(networks, key=lambda x: x['signal'], reverse=True)

def scan_nearby_wifi_linux():
    networks = []
    try:
        cmd = ["nmcli", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY,FREQ", "dev", "wifi"]
        output = subprocess.check_output(cmd, encoding="utf-8", errors="ignore")
        lines = output.strip().splitlines()

        if len(lines) > 1:
            for line in lines[1:]:
                parts = re.split(r'\s{2,}', line.strip())
                if len(parts) >= 5:
                    ssid = parts[0] if parts[0] == "--" else "[Hidden SSID]"
                    bssid = parts[1]
                    signal = int(parts[2]) if parts[2].isdigit else 0
                    channel = parts[3]
                    security = parts[4]
                    freq = parts[5] if len(parts) > 5 else "N/A"

                    networks.append({
                        "ssid": ssid,
                        "bssid": bssid,
                        "signal": signal,
                        "channel": f"{channel} ({freq})",
                        "auth": security,
                        "radio": "Linux Wlan" 
                    })
    except Exception:
        pass

    return sorted(networks, key=lambda x: x["signal"], reverse=True)

def get_wifi_profile_windows():
    profiles_data = []
    try:
        output = subprocess.check_output(["netsh", "wlan", "show", "profiles"], encoding="utf-8", errors="ignore")
        profile_names = re.findall(r"All User Profile\s*:\s*(.*)", output)

        for name in profile_names:
            name = name.strip()

            try:
                profile_info = subprocess.check_output(
                    ["netsh", "wlan", "show", "profile", f"name={name}", "key=clear"], 
                    encoding="utf-8", 
                    errors="ignore"
                )
                password_match = re.search(r"Key Content\s*:\s*(.*)", profile_info)
                password = password_match.group(1).strip() if password_match else "[Dim/None]"
            except Exception:
                password = "[Gagal Dibaca]"
            profiles_data.append({"ssid": name, "password": password})
    except Exception as e:
        console.print(f"[bold red]Gagal mengambil data Wi-Fi di Windows: {e}[/bold red]")

    return profiles_data

def get_wifi_profiles_linux():
    profiles_data = []
    try:
        connections_dir = "/etc/NetworkManager/system-connections/"
        if os.path.exists(connections_dir):
            for file in os.listdir(connections_dir):
                if file.endswith(".nmconnection"):
                    ssid = file.replace(".nmconnection", "")
                    password = "[Protected/Root Needed]",
                    profiles_data.append({"ssid": ssid, "password": password})
        else:
            output = subprocess.check_output(["nmcli", "-t", "-f", "SSID", "dev", "wifi"], encoding="utf-8", errors="ignore")
            ssids = list(set([line.strip() for line in output.splitlines() if line.strip()]))
            for ssid in ssids:
                profiles_data.append({"ssid": ssid, "password": "[N/A]"})
    except Exception:
        pass
    return profiles_data

def get_wifi_profiles():
    if os.name == "nt":
        return get_wifi_profile_windows()
    else:
        return get_wifi_profiles_linux()

def run():
    try:
        while True:
            console.clear()
            console.print("[bold cyan]🔍 Memindai jaringan Wi-Fi sekitar & detail signal...[/bold cyan]\n")

            if os.name == "nt":
                networks = scan_nearby_wifi_windows()
            else:
                networks = scan_nearby_wifi_linux()

            console.clear()

            if not networks:
                console.print("[yellow]Tidak ada jaringan Wi-Fi terditeksi atau Wi-Fi adapter mati.[/yellow]")
            else:
                table = Table(title=f"[bold green]Daftar Jaringan Wi-Fi Sekitar ({len(networks)} Terditeksi)[/bold green]", expand=True)
                table.add_column("No", style="dim", width=4)
                table.add_column("SSID (Nama)", style="bold cyan")
                table.add_column("Kekuatan Sinyal", style="bold white")
                table.add_column("MAC Address (BSSID)", style="dim white")
                table.add_column("Ch", style="yellow", justify="center")
                table.add_column("Keamanan", style="magenta")
                table.add_column("Standar Radio", style="blue")

                for idx, net in enumerate(networks, start=1):
                    table.add_row(
                        str(idx),
                        str(net['ssid']),
                        get_signal_bar(net['signal']),
                        str(net['bssid']),
                        str(net['channel']),
                        str(net['auth']),
                        str(net['radio'])
                    )

                console.print(table)

            console.print("\n[bold white]Opsi Tambahan:[/bold white]")
            console.print("\n[bold cyan]1. Refresh / Pindai Ulang[/bold cyan]")
            console.print("\n[bold cyan]2. Lihat Password Wi-Fi Tersimpan Di Komputer[/bold cyan]")
            console.print("\n[bold cyan]0. Kembali ke Menu Utama ToolsDong[/bold cyan]")
            
            flush_input()
            pilihan = Prompt.ask("\nPilih opsi")

            if pilihan == "1":
                continue
            elif pilihan == "2":
                try:
                    console.clear()

                    console.print("[bold cyan]🔍 Memindai profil Wi-Fi tersimpan di perangkat...[/bold cyan]")

                    profiles = get_wifi_profiles()

                    console.clear()

                    if not profiles:
                        console.print("[yellow]Tidak ditemukan profile Wi-Fi tersimpan atau akses dibatasi.[/yellow]")
                    else:
                        saved = Table(title="[bold green]Daftar Wi-Fi & Password Tersimpan[/bold green]")
                        saved.add_column("No", style="dim", width=6)
                        saved.add_column("Nama Wi-Fi (SSID)", style="bold cyan")
                        saved.add_column("Password / Key", style="bold yellow")

                        for idx, item in enumerate(profiles, start=1):
                            saved.add_row(str(idx), item['ssid'], item['password'])

                        console.print(saved)
                    Prompt.ask("\nTekan Enter untuk kembali...")
                except KeyboardInterrupt:
                    console.print("[bold yellow]Kembali ke scan...[/bold yellow]")
            elif pilihan == "0":
                break
    except KeyboardInterrupt:
        console.print("\n[bold yellow]\n[!] Keluar dari Wi-Fi Tools... Kembali ke Menu Utama.[/bold yellow]")