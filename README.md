# 🛠️ ToolsDong

ToolsDong adalah aplikasi CLI berbasis Python untuk analisis jaringan Wi-Fi, pemindaian sinyal secara real-time, dan manajemen profil Wi-Fi tersimpan.

## 🚀 Fitur Utama
- **System Resource Monitoring**: Monitor resource system anda seperti CPU, RAM, GPU, dan top program by RAM.
- **Scan Wi-Fi Sekitar**: Menampilkan SSID, MAC Address (BSSID), Channel, Keamanan, dan Indikator Sinyal.
- **Lihat Password Tersimpan**: Membaca profil Wi-Fi beserta password yang pernah terhubung di perangkat.
- **Dukungan Lintas Platform**: Kompatibel dengan Windows dan Linux (`nmcli`).

## ⚙ Requierments
- Python 3.13.0

## 💻 Cara Install & Menjalankan

1. **Clone Repositori**
    ```bash
    git clone [https://github.com/username-kamu/ToolsDong.git](https://github.com/username-kamu/ToolsDong.git)
    cd ToolsDong

2. **Buat & Aktifkan Virtual Environment**
    ```bash
    # Windows
    python -m venv env
    .\env\Scripts\activate

    # Linux / macOS
    python3 -m venv env
    source env/bin/activate

3. **Install Dependensi**
    ```bash
    pip install -r requirements.txt

4. **Jalankan Aplikasi**
    ```bash
    python main.py