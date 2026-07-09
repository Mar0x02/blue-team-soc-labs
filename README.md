# 🛡️ Blue Team SOC Labs

Selamat datang di **Blue Team SOC Labs**! 🚀

Repo ini adalah dokumentasi, *blueprint*, dan *knowledge base* dari home lab khusus **Blue Team (Detection & Response)** yang aku bangun. Fokus utama dari lab ini bukan cuma buat nge-hack, tapi lebih ke **gimana cara nge-detect, nge-analisis, dan nge-response** terhadap sistem yang udah ter-kompromi.

Lab ini dirancang untuk mensimulasikan lingkungan enterprise nyata, lengkap dengan SIEM, Firewall, Active Directory, dan integrasi AI untuk membantu analisis alert.

---

## 🖥️ Hardware & Device Architecture

Lab ini dijalankan menggunakan 3 device utama dengan pembagian tugas yang spesifik:

### 1. PC Utama (The VM Host)
*   **Spesifikasi:** AMD Ryzen 7 5700G | RAM 32 GB | SSD 512 GB | PSU Helio M1
*   **Peran:** Bertindak sebagai *hypervisor* (menggunakan VirtualBox/VMware/Proxmox) untuk menjalankan seluruh infrastruktur virtual (VM) dari lab ini.

### 2. Laptop Windows (Dell)
*   **Peran:** Dedicated **SIEM Server**.
*   **Fungsi:** Menjalankan **Wazuh Manager** (dan dashboard Wazuh/Kibana). Device ini akan menerima, memproses, dan memvisualisasikan seluruh log dan alert dari VM-VM yang ada di PC Utama.

### 3. Laptop Mac (M1)
*   **Peran:** **AI & Automation Brain**.
*   **Fungsi:** Menjalankan **Ollama** dan pipeline **RAG (Retrieval-Augmented Generation)**. Device ini akan menerima alert dari SIEM (Wazuh) dan menggunakan AI untuk melakukan triage otomatis, merangkum insiden, atau memberikan rekomendasi respons dalam bahasa manusia.

---

## 🌐 Virtual Infrastructure (The Lab Network)

Infrastruktur virtual di bawah ini adalah **baseline (standar)** yang berjalan di PC Utama. 

> **Catatan:** VM-VM ini bisa saja berubah, ditambah, atau dikurangi tergantung pada skenario lab spesifik yang sedang dijalankan. Setiap perubahan atau spesifikasi khusus untuk skenario tertentu akan didokumentasikan di dalam folder `labs/`.

| VM Name | OS / Role | Deskripsi & Fungsi |
| :--- | :--- | :--- |
| **pfSense** | pfSense / Firewall | Bertindak sebagai *Gateway*, *Router*, dan *Firewall* untuk memisahkan zona jaringan LAN1 (Server) dan LAN2 (Host). |
| **Ubuntu Server** | Ubuntu Server + DVWA | Target server. Di-install **DVWA** (Damn Vulnerable Web App) untuk simulasi kerentanan web. IP: `10.10.10.10` |
| **Windows Server** | Windows Server (AD DC) | Bertindak sebagai **Domain Controller** (Active Directory). Mengelola user, group policy, dan autentikasi terpusat. IP: `10.10.10.20` |
| **Windows 7** | Windows 7 | *Victim Workstation*. Target utama simulasi phishing, ransomware, dan lateral movement. IP: `10.10.20.10` |
| **Windows XP** | Windows XP | *Victim Workstation* legacy. Simulasi endpoint lama tanpa patch. IP: `10.10.20.20` |
| **Ubuntu Host** | Ubuntu Desktop | *Victim Workstation* Linux. Simulasi serangan di lingkungan Linux. IP: `10.10.20.30` |
| **Kali Linux** | Kali Linux (External Attacker) | Mesin penyerang. Posisi **di luar firewall** (hotspot `192.168.43.x`) — mensimulasikan external attacker yang menyerang via internet/WAN pfSense. |

---

## 🧠 Lab Philosophy & Rules

1.  **Detection First:** Kita tidak cuma fokus pada "gimana cara nge-exploit", tapi "gimana cara SIEM nge-detect exploit tersebut" dan "gimana cara AI nge-rangkum alert-nya".
2.  **External Attacker Simulation:** Kali Linux diposisikan di luar firewall (hotspot) sebagai external attacker — menyerang via WAN pfSense untuk mensimulasikan serangan dari internet. Ini memaksa traffic melewati pfSense sehingga bisa dilog dan dideteksi.
3.  **Dynamic Environments:** Daftar VM di atas adalah *base environment*. Jika ada lab yang butuh VM tambahan (misal: database server, mail server), detailnya akan ditulis di `Labs/[nama-lab]/README.md`.
4.  **AI-Assisted SOC:** Memanfaatkan Mac M1 untuk mengubah log mentah yang membingungkan menjadi insight yang bisa dibaca oleh analis L1.

---

## ✅ Status Progress

| Komponen | Status | Keterangan |
| :--- | :---: | :--- |
| Dell — Ubuntu Server + Wazuh All-in-One | ✅ Done | Running, dashboard accessible |
| M1 — Ollama + model stack | ✅ Done | `llama3.2:1b`, `3b`, `qwen2.5:4b`, `nomic-embed-text` ter-pull |
| M1 — RAG pipeline (ingest scripts) | ✅ Done | 5 script ingest: Sigma, YARA, MITRE, CVE, THM |
| M1 — ChromaDB vector database | ✅ Done | Data Sigma + YARA + MITRE + CVE 2022–2026 ter-ingest |
| PC — VM infrastructure | ⏳ Pending | PC belum datang, VirtualBox/Proxmox belum di-setup |
| pfSense Firewall | ⏳ Pending | Menunggu PC |
| Web Server (DVWA) | ⏳ Pending | Menunggu PC |
| Windows AD Domain Controller | ⏳ Pending | Menunggu PC |
| Windows 7 (Victim) | ⏳ Pending | Menunggu PC |
| Windows XP (Victim Legacy) | ⏳ Pending | Menunggu PC |
| Ubuntu Host (Victim Linux) | ⏳ Pending | Menunggu PC |
| Kali Linux (External Attacker) | ⏳ Pending | Di hotspot, tidak butuh VM di PC |
| Wazuh Agent di VM-VM | ⏳ Pending | Menunggu VM infrastructure |
| Integrasi Wazuh → Ollama (alert forwarding) | ⏳ Pending | Menunggu VM + agent setup |

---

## 📂 Repository Structure

Repo ini dibagi menjadi beberapa folder utama untuk merapikan aset lab:

```text
blue-team-soc-labs/
├── Infrastructure/              # Setup docs: network topology, Wazuh, Ollama.
│   ├── asset/                   # Screenshots & diagram jaringan.
│   ├── network-topology.md      # Topologi jaringan lab lengkap.
│   ├── wazuh-setup.md           # Panduan instalasi Wazuh All-in-One.
│   └── ollama-installation.md   # Panduan instalasi Ollama + model stack.
├── Labs/                        # Skenario lab spesifik (Writeup, steps, & attack simulations).
├── Detection-Engineer/          # Custom rules Wazuh, Sigma rules, dan Yara rules.
├── Incident-Response/           # SOP, Playbooks, dan template Incident Report.
├── AI-Rag-Integration/          # Script Python dan pipeline RAG untuk Ollama.
│   ├── ingest-thm.py            # Ingest TryHackMe writeups (MD/PDF).
│   ├── ingest-yara.py           # Ingest YARA rules.
│   ├── ingest-yml.py            # Ingest Sigma rules.
│   ├── ingest-mitre.py          # Ingest MITRE ATT&CK (STIX/JSON).
│   ├── ingest-cve.py            # Ingest CVE database (JSON v5).
│   ├── requirements.txt         # Python dependencies.
│   └── README.md                # Dokumentasi lengkap pipeline RAG.
└── README.md                    # File yang sedang kamu baca ini.