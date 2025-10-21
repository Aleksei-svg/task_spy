import os
import json
import subprocess
import psutil
import requests
import wmi
import winreg
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
from pandastable import Table
import pandas as pd
from colorama import Fore, init
import threading
import queue

try:
    import win32api
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False

init(autoreset=True)

# ========================= Настройки ===============================
ABUSEIPDB_API_KEY = ''
VIRUSTOTAL_API_KEY = ''
SETTINGS_FILE = 'threat_hunter_settings.json'
REPORT_FILE = 'threat_hunter_report.json'

# ========================= Списки для анализа ===============================
SUSPICIOUS_NAMES = ['svshost', 'chrome_update', 'winlogin', 'serviceshost', 'svchost.exe', 'lsass.exe', 'wininit.exe']
SUSPICIOUS_LOCATIONS = ['\\appdata\\', '\\temp\\', '\\programdata\\']
SYSTEM32_PATH = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32').lower()
TARGET_EXTENSIONS = [
    '.py', '.bat', '.ps1', '.vbs', '.js', '.wsf', '.hta', '.lnk',
    '.scf', '.url', '.reg', '.dll', '.sys', '.tmp', '.exe',
    '.php', '.jsp', '.aspx', '.phtml', '.pl', '.cgi',
    '.b64', '.enc', '.dat', '.bin', '.cache'
]

# ========================= YARA ===============================
try:
    import yara
    YARA_SUPPORTED = True
except ImportError:
    YARA_SUPPORTED = False

YARA_RULES = """
rule Suspicious_Powershell_Encoding {
    meta:
        description = "Зашифрованный PowerShell"
    strings:
        $enc1 = /powershell.*-enc.*/i
        $enc2 = /cmd.* \\/c.*echo/i
    condition:
        $enc1 or $enc2
}
rule Malicious_Shellcode {
    meta:
        description = "Shellcode и syscall-инструкции"
    strings:
        $sysenter = { 0F 34 }
        $syscall = { 0F 05 }
        $jmp_rax = { FF E0 }
        $call_rax = { FF D0 }
    condition:
        any of them
}
rule C2_Communication {
    meta:
        description = "Подозрительные HTTP-запросы, характерные для C2"
    strings:
        $c2_get = /GET \/update\.php\?id=/ nocase
        $c2_post = /POST \/gate\.php/ nocase
        $c2_useragent = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
    condition:
        1 of ($c2_*) or $c2_useragent
}
rule InMemory_PE_Header {
    meta:
        description = "Обнаружен заголовок PE-файла (MZ) в памяти, что может указывать на Reflective DLL Injection."
    strings:
        $mz = "MZ"
        $pe = "PE"
    condition:
        $mz at 0 and $pe
}
"""

def compile_yara_rules():
    if not YARA_SUPPORTED:
        return None
    try:
        return yara.compile(source=YARA_RULES)
    except Exception as e:
        print(Fore.RED + f"[!] Ошибка YARA: {str(e)}")
        return None

def scan_with_yara_file(file_path, rules):
    if not YARA_SUPPORTED or not rules or not os.path.isfile(file_path):
        return []
    try:
        matches = rules.match(filepath=file_path)
        return [match.rule for match in matches]
    except Exception:
        return []

def scan_with_yara_memory(pid, rules):
    if not YARA_SUPPORTED or not rules:
        return []
    try:
        matches = rules.match(pid=pid)
        return [match.rule for match in matches]
    except yara.Error:
        return []
    except Exception:
        return []

# ========================= Внешние API ===============================
def check_ip_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        messagebox.showwarning("Нет ключа", "API ключ для AbuseIPDB не указан в настройках.")
        return
    
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    try:
        response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()['data']
            info = (
                f"IP-адрес: {data['ipAddress']}\n"
                f"Страна: {data.get('countryName', 'N/A')}\n"
                f"Домен: {data.get('domain', 'N/A')}\n"
                f"Количество жалоб: {data['totalReports']}\n"
                f"Рейтинг опасности: {data['abuseConfidenceScore']}%"
            )
            messagebox.showinfo("Отчет AbuseIPDB", info)
        else:
            messagebox.showerror("Ошибка API", f"Ошибка: {response.status_code}\n{response.text}")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось подключиться к AbuseIPDB: {e}")

# ========================= Вспомогательные функции ===============================
def get_file_signature_info(file_path):
    if not PYWIN32_AVAILABLE or not os.path.isfile(file_path):
        return "Нет данных", False
    try:
        info = win32api.GetFileVersionInfo(file_path, '\\')
        lang_codepage = win32api.GetFileVersionInfo(file_path, '\\VarFileInfo\\Translation')[0]
        string_file_info_path = f'\\StringFileInfo\\{lang_codepage:04x}{lang_codepage >> 16:04x}\\CompanyName'
        company = win32api.GetFileVersionInfo(file_path, string_file_info_path)
        is_microsoft = "microsoft" in company.lower()
        return company, is_microsoft
    except Exception:
        return "Нет подписи", False

# ========================= Сканеры системы ===============================
def scan_suspicious_processes(yara_rules=None):
    results = []
    legitimate_parents = {
        'services.exe': ['wininit.exe'],
        'svchost.exe': ['services.exe'],
        'explorer.exe': ['userinit.exe'],
        'lsass.exe': ['wininit.exe'],
    }
    attrs = ['pid', 'name', 'exe', 'cmdline', 'username', 'ppid', 'create_time']
    for proc in psutil.process_iter(attrs):
        try:
            info = proc.info
            exe_path = info.get('exe')
            name = info.get('name') or ''
            
            if exe_path and exe_path.lower().startswith(SYSTEM32_PATH):
                _, is_microsoft = get_file_signature_info(exe_path)
                if is_microsoft:
                    continue

            suspicion_score = 0
            reasons = []

            if any(loc in (exe_path or '').lower() for loc in SUSPICIOUS_LOCATIONS):
                suspicion_score += 20
                reasons.append("📁 Путь из Temp/AppData")

            if name.lower() in SUSPICIOUS_NAMES and exe_path and not exe_path.lower().startswith(SYSTEM32_PATH):
                suspicion_score += 40
                reasons.append(f"🕵 Имя '{name}' вне System32")
            
            parent_name = ''
            try:
                parent_proc = proc.parent()
                if parent_proc:
                    parent_name = parent_proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            if name.lower() in legitimate_parents and parent_name.lower() not in legitimate_parents[name.lower()]:
                 suspicion_score += 30
                 reasons.append(f"🧬 Нетипичный родитель: {parent_name}")

            cmdline = ' '.join(info['cmdline']) if info.get('cmdline') else ''
            if "powershell" in cmdline.lower() and "-enc" in cmdline.lower():
                suspicion_score += 60
                reasons.append("🔐 Зашифрованный PowerShell")

            if yara_rules and exe_path and os.path.isfile(exe_path):
                yara_matches = scan_with_yara_file(exe_path, yara_rules)
                if yara_matches:
                    suspicion_score += 100 * len(yara_matches)
                    reasons.extend([f"⚠ YARA [file]: {rule}" for rule in yara_matches])
            
            if yara_rules:
                yara_mem_matches = scan_with_yara_memory(info['pid'], yara_rules)
                if yara_mem_matches:
                    suspicion_score += 150 * len(yara_mem_matches)
                    reasons.extend([f"🔥 YARA [memory]: {rule}" for rule in yara_mem_matches])

            if suspicion_score > 0:
                company, _ = get_file_signature_info(exe_path)
                results.append({
                    'Рейтинг': suspicion_score, 'PID': info['pid'], 'Имя': name,
                    'Путь': exe_path, 'Подпись': company, 'Аргументы': cmdline,
                    'Пользователь': info.get('username'),
                    'Родитель': f"{parent_name} ({info['ppid']})",
                    'Старт': datetime.fromtimestamp(info['create_time']).strftime('%Y-%m-%d %H:%M:%S'),
                    'Причины': ', '.join(reasons)
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(results, key=lambda x: x['Рейтинг'], reverse=True)

def collect_autoruns_registry():
    entries = []
    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Active Setup\Installed Components"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Active Setup\Installed Components"),
    ]
    for root, path in keys:
        try:
            reg_key = winreg.OpenKey(root, path)
            for i in range(1024):
                try:
                    name, val, _ = winreg.EnumValue(reg_key, i)
                    entries.append({'Источник': f"{'HKCU' if root == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{path}", 'Имя': name, 'Команда': val})
                except OSError:
                    break
        except FileNotFoundError:
            continue
    return entries

def collect_ifeo_hijacks():
    entries = []
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        for i in range(1024):
            try:
                exe_name = winreg.EnumKey(reg_key, i)
                sub_key_path = f"{path}\\{exe_name}"
                sub_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub_key_path)
                try:
                    debugger_val, _ = winreg.QueryValueEx(sub_key, "Debugger")
                    if debugger_val:
                        entries.append({'Перехватываемый процесс': exe_name, 'Запускаемая программа (Debugger)': debugger_val})
                except FileNotFoundError:
                    pass
                winreg.CloseKey(sub_key)
            except OSError:
                break
        winreg.CloseKey(reg_key)
    except FileNotFoundError:
        pass
    return entries

def collect_startup_folders():
    entries = []
    folders = [
        os.path.join(os.environ['APPDATA'], 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
        os.path.join(os.environ.get('ALLUSERSPROFILE', 'C:\\ProgramData'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
    ]
    for folder in folders:
        if os.path.exists(folder):
            for file in os.listdir(folder):
                full_path = os.path.join(folder, file)
                entries.append({'Папка': folder, 'Файл': file, 'Полный путь': full_path})
    return entries

def collect_scheduled_tasks_full():
    tasks = []
    try:
        cmd = ["schtasks", "/query", "/fo", "LIST", "/v"]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='cp866', errors='ignore')
        blocks = result.stdout.strip().split("\n\n")
        for b in blocks:
            data = {}
            lines = b.splitlines()
            for line in lines:
                if ':' in line:
                    k, v = line.split(':', 1)
                    data[k.strip()] = v.strip()
            if data and ("powershell" in str(data).lower() or any(ext in str(data).lower() for ext in TARGET_EXTENSIONS)):
                 tasks.append(data)
    except Exception as e:
        print(f"Ошибка schtasks: {str(e)}")
    return tasks

def collect_wmi_tasks():
    try:
        return [{'Имя': i.Name, 'Команда': i.Command, 'Пользователь': i.User} for i in wmi.WMI().Win32_StartupCommand()]
    except Exception as e:
        # Теперь мы не молчим, а сообщаем о проблеме
        print(Fore.RED + f"[!] Не удалось получить WMI-задачи: {e}")
        return []

def collect_services():
    try:
        return [{'Имя': x.Name, 'Отображаемое имя': x.DisplayName, 'Путь': x.PathName} for x in wmi.WMI().Win32_Service() if x.StartMode == "Auto"]
    except Exception as e:
        # И здесь тоже сообщаем
        print(Fore.RED + f"[!] Не удалось получить список служб: {e}")
        return []

def collect_network_connections():
    connections = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            conns = proc.connections(kind='inet')
            for conn in conns:
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    connections.append({
                        'PID': proc.info['pid'], 'Процесс': proc.info['name'],
                        'Локальный адрес': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'Удаленный адрес': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'Статус': conn.status
                    })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return connections

# ========================= Интерфейс ===============================
class ThreatHunterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔥 Threat Hunter Suite — Анализ системы, памяти и сети")
        self.root.geometry("1400x800")
        self.settings = self.load_settings()
        self.yara_rules = compile_yara_rules()
        self.data_queue = queue.Queue()

        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Обновить всё", command=self.start_refresh)
        filemenu.add_separator()
        filemenu.add_command(label="Выход", command=self.root.quit)
        menubar.add_cascade(label="Файл", menu=filemenu)
        self.root.config(menu=menubar)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True)

        self.proc_frame = ttk.Frame(self.notebook)
        self.net_frame = ttk.Frame(self.notebook)
        self.auto_frame = ttk.Frame(self.notebook)
        self.ifeo_frame = ttk.Frame(self.notebook)
        self.start_frame = ttk.Frame(self.notebook)
        self.sched_frame = ttk.Frame(self.notebook)
        self.wmi_frame = ttk.Frame(self.notebook)
        self.serv_frame = ttk.Frame(self.notebook)
        self.sett_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.proc_frame, text=" suspicious Процессы")
        self.notebook.add(self.net_frame, text="📡 Сетевая активность")
        self.notebook.add(self.auto_frame, text="Автозагрузка (Реестр)")
        self.notebook.add(self.ifeo_frame, text="Перехват запуска (IFEO)")
        self.notebook.add(self.start_frame, text="Папки автозагрузки")
        self.notebook.add(self.sched_frame, text="Задачи планировщика")
        self.notebook.add(self.wmi_frame, text="WMI автозапуск")
        self.notebook.add(self.serv_frame, text="Службы Windows")
        self.notebook.add(self.sett_frame, text="Настройки")

        self.refresh_btn = ttk.Button(self.root, text="🔄 Обновить всё", command=self.start_refresh)
        self.refresh_btn.pack(pady=5)
        
        ttk.Label(self.sett_frame, text="VirusTotal API Key:").pack(anchor='w', padx=10, pady=5)
        self.vt_api_entry = ttk.Entry(self.sett_frame, width=60)
        self.vt_api_entry.pack(padx=10, pady=5)
        self.vt_api_entry.insert(0, self.settings.get('virustotal_api_key', ''))

        ttk.Label(self.sett_frame, text="AbuseIPDB API Key:").pack(anchor='w', padx=10, pady=(15, 5))
        self.abuse_api_entry = ttk.Entry(self.sett_frame, width=60)
        self.abuse_api_entry.pack(padx=10, pady=5)
        self.abuse_api_entry.insert(0, self.settings.get('abuseipdb_api_key', ''))

        self.save_api_btn = ttk.Button(self.sett_frame, text="💾 Сохранить ключи", command=self.save_api_keys)
        self.save_api_btn.pack(padx=10, pady=10)

        self.proc_table = self.create_table(self.proc_frame)
        self.net_table = self.create_table(self.net_frame)
        self.auto_table = self.create_table(self.auto_frame)
        self.ifeo_table = self.create_table(self.ifeo_frame)
        self.start_table = self.create_table(self.start_frame)
        self.sched_table = self.create_table(self.sched_frame)
        self.wmi_table = self.create_table(self.wmi_frame)
        self.serv_table = self.create_table(self.serv_frame)
        
        self.net_context_menu = tk.Menu(self.root, tearoff=0)
        self.net_context_menu.add_command(label="Проверить IP на AbuseIPDB", command=self.check_selected_ip)
        self.net_table.bind("<Button-3>", self.show_net_menu)

        self.start_refresh()

    def create_table(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill='both', expand=True)
        pt = Table(frame, showtoolbar=False, showstatusbar=True)
        pt.show()
        return pt

    def start_refresh(self):
        self.refresh_btn.config(state="disabled", text="🔄 Идет сканирование...")
        scan_thread = threading.Thread(target=self.run_scan_and_update_queue, daemon=True)
        scan_thread.start()
        self.process_queue()

    def run_scan_and_update_queue(self):
        self.data_queue.put(('proc', scan_suspicious_processes(self.yara_rules)))
        self.data_queue.put(('net', collect_network_connections()))
        self.data_queue.put(('auto', collect_autoruns_registry()))
        self.data_queue.put(('ifeo', collect_ifeo_hijacks()))
        self.data_queue.put(('start', collect_startup_folders()))
        self.data_queue.put(('sched', collect_scheduled_tasks_full()))
        self.data_queue.put(('wmi', collect_wmi_tasks()))
        self.data_queue.put(('serv', collect_services()))
        self.data_queue.put(('finished', None))

    def process_queue(self):
        try:
            key, data = self.data_queue.get_nowait()
            
            if key == 'proc': self.update_table(self.proc_table, data)
            elif key == 'net': self.update_table(self.net_table, data)
            elif key == 'auto': self.update_table(self.auto_table, data)
            elif key == 'ifeo': self.update_table(self.ifeo_table, data)
            elif key == 'start': self.update_table(self.start_table, data)
            elif key == 'sched': self.update_table(self.sched_table, data)
            elif key == 'wmi': self.update_table(self.wmi_table, data)
            elif key == 'serv': self.update_table(self.serv_table, data)
            elif key == 'finished':
                self.refresh_btn.config(state="normal", text="🔄 Обновить всё")
                return
            
            self.root.after(100, self.process_queue)
        except queue.Empty:
            self.root.after(100, self.process_queue)

    def update_table(self, table_widget, data):
        df = pd.DataFrame(data)
        table_widget.model.df = df
        table_widget.redraw()
    
    def save_api_keys(self):
        vt_key = self.vt_api_entry.get().strip()
        abuse_key = self.abuse_api_entry.get().strip()
        self.settings['virustotal_api_key'] = vt_key
        self.settings['abuseipdb_api_key'] = abuse_key
        global VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
        VIRUSTOTAL_API_KEY = vt_key
        ABUSEIPDB_API_KEY = abuse_key
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.settings, f, indent=2, ensure_ascii=False)
        messagebox.showinfo("✅", "API ключи сохранены")

    def load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    s = json.load(f)
                    global VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
                    VIRUSTOTAL_API_KEY = s.get('virustotal_api_key', '')
                    ABUSEIPDB_API_KEY = s.get('abuseipdb_api_key', '')
                    return s
            except Exception:
                pass
        return {}

    def show_net_menu(self, event):
        self.net_context_menu.post(event.x_root, event.y_root)

    def check_selected_ip(self):
        if not self.net_table.model.df.empty:
            row = self.net_table.getSelectedRow()
            if row is not None and row < len(self.net_table.model.df):
                ip_with_port = self.net_table.model.df.iloc[row]['Удаленный адрес']
                ip = ip_with_port.split(':')[0]
                check_ip_abuseipdb(ip)

# ========================== MAIN ==============================
if __name__ == '__main__':
    if not PYWIN32_AVAILABLE:
        messagebox.showerror("Ошибка", "Библиотека pywin32 не найдена.\nПожалуйста, установите ее: pip install pywin32")
        exit()
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        messagebox.showerror("Ошибка", "Программа должна быть запущена от имени администратора!")
        exit()
    root = tk.Tk()
    app = ThreatHunterGUI(root)
    root.mainloop()
