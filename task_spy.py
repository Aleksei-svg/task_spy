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
init(autoreset=True)

# ========================= Настройки ===============================
VIRUSTOTAL_API_KEY = ''
SETTINGS_FILE = 'task_spy_settings.json'
REPORT_FILE = 'task_spy_report_full.json'

# ========================= Системные данные ===============================
wmi_conn = wmi.WMI()

TARGET_EXTENSIONS = ['.py', '.bat', '.ps1']
SUSPICIOUS_NAMES = ['svshost', 'chrome_update', 'winlogin', 'serviceshost']
SUSPICIOUS_LOCATIONS = ['\\appdata\\', '\\temp\\', '\\programdata\\']
SUSPICIOUS_EXTENSIONS = ['.pif', '.scr', '.com', '.dat', '.cpl']

# ========================= Проверка администраторских прав ===============================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# ========================= Хэширование и VT ===============================
def hash_file(path):
    if not path or not os.path.isfile(path):
        return None
    import hashlib
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def query_virustotal(file_hash, api_key):
    if not file_hash or not api_key:
        return '—'
    try:
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}' 
        headers = {'x-apikey': api_key}
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            return f"{stats['malicious']}/{sum(stats.values())} детектов"
        else:
            return f"VT ошибка: {resp.status_code}"
    except Exception as e:
        return f"VT ошибка: {str(e)}"

# ========================= Сканеры ===============================
def find_script_processes():
    found = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'ppid']):
        try:
            cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
            if any(ext in cmdline.lower() for ext in TARGET_EXTENSIONS):
                found.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cmdline': cmdline,
                    'username': proc.info['username'],
                    'ppid': proc.info['ppid']
                })
        except Exception:
            continue
    return found

def is_suspicious_path(path): return any(loc in (path or '').lower() for loc in SUSPICIOUS_LOCATIONS)
def is_suspicious_name(name): return any(name.lower().startswith(sus) for sus in SUSPICIOUS_NAMES)
def is_suspicious_ext(path): return any(path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)

def scan_suspicious_processes():
    results = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'ppid', 'create_time']):
        try:
            info = proc.info
            name = info['name'] or ''
            exe = info['exe'] or ''
            cmdline = ' '.join(info['cmdline']) if info['cmdline'] else ''
            reasons = []

            if is_suspicious_path(exe): reasons.append("📁 Путь из Temp/AppData")
            if is_suspicious_name(name): reasons.append("🕵 Имя как у системного процесса")
            if is_suspicious_ext(exe): reasons.append("📦 Странное расширение")
            if info['ppid'] in (0, 4): reasons.append("🧬 Родитель PID = 0 / 4")
            if "powershell" in cmdline.lower() and "-enc" in cmdline.lower(): reasons.append("🔐 Зашифрованный PowerShell")

            if reasons:
                results.append({
                    'PID': info['pid'],
                    'Имя': name,
                    'Путь': exe,
                    'Аргументы': cmdline,
                    'Пользователь': info['username'],
                    'Родительский PID': info['ppid'],
                    'Старт': datetime.fromtimestamp(info['create_time']).strftime('%Y-%m-%d %H:%M:%S'),
                    'Причины': ', '.join(reasons)
                })
        except Exception:
            continue
    return results

def collect_autoruns_registry():
    entries = []
    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
    ]
    for root, path in keys:
        try:
            reg_key = winreg.OpenKey(root, path)
            for i in range(100):
                try:
                    name, val, _ = winreg.EnumValue(reg_key, i)
                    entries.append({
                        'Источник': f"{'HKCU' if root == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{path}",
                        'Имя': name,
                        'Команда': val
                    })
                except OSError:
                    break
        except Exception:
            continue
    return entries

def collect_startup_folders():
    entries = []
    folders = [
        os.path.join(os.environ['APPDATA'], 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
        os.path.join(os.environ['PROGRAMDATA'], 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
    ]
    for folder in folders:
        if os.path.exists(folder):
            for file in os.listdir(folder):
                full_path = os.path.join(folder, file)
                entries.append({
                    'Папка': folder,
                    'Файл': file,
                    'Полный путь': full_path
                })
    return entries

def collect_scheduled_tasks_full():
    tasks = []
    try:
        result = subprocess.run(["schtasks", "/query", "/fo", "LIST", "/v"], capture_output=True, text=True, shell=True)
        blocks = result.stdout.split("\r\n\r\n")
        for b in blocks:
            if "powershell" in b.lower() or any(ext in b.lower() for ext in TARGET_EXTENSIONS):
                data = {}
                for line in b.splitlines():
                    if ':' in line:
                        k, v = line.split(':', 1)
                        data[k.strip()] = v.strip()
                if data:
                    tasks.append(data)
    except Exception:
        pass
    return tasks

def collect_wmi_tasks():
    try:
        return [{
            'Имя': i.Name,
            'Команда': i.Command,
            'Пользователь': i.User
        } for i in wmi_conn.Win32_StartupCommand()]
    except Exception:
        return []

def collect_services():
    try:
        return [{
            'Имя': x.Name,
            'Отображаемое имя': x.DisplayName,
            'Путь': x.PathName
        } for x in wmi_conn.Win32_Service() if x.StartMode == "Auto" and x.State == "Running"]
    except Exception:
        return []

# ========================= Интерфейс ===============================
class TaskSpyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Task Spy ULTIMATE")
        self.root.geometry("1400x800")
        self.settings = self.load_settings()

        # Меню
        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Обновить всё", command=self.refresh_all)
        filemenu.add_separator()
        filemenu.add_command(label="Выход", command=self.root.quit)
        menubar.add_cascade(label="Файл", menu=filemenu)
        self.root.config(menu=menubar)

        # Вкладки
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True)

        self.proc_frame = ttk.Frame(self.notebook)
        self.auto_frame = ttk.Frame(self.notebook)
        self.start_frame = ttk.Frame(self.notebook)
        self.sched_frame = ttk.Frame(self.notebook)
        self.wmi_frame = ttk.Frame(self.notebook)
        self.serv_frame = ttk.Frame(self.notebook)
        self.sett_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.proc_frame, text="Процессы")
        self.notebook.add(self.auto_frame, text="Автозагрузка")
        self.notebook.add(self.start_frame, text="Папки автозагрузки")
        self.notebook.add(self.sched_frame, text="Задачи планировщика")
        self.notebook.add(self.wmi_frame, text="WMI автозапуск")
        self.notebook.add(self.serv_frame, text="Службы")
        self.notebook.add(self.sett_frame, text="Настройки")

        # Кнопка обновления
        self.refresh_btn = ttk.Button(self.root, text="🔄 Обновить всё", command=self.refresh_all)
        self.refresh_btn.pack(pady=5)

        # Настройки
        ttk.Label(self.sett_frame, text="VirusTotal API Key:").pack(anchor='w', padx=10, pady=5)
        self.api_entry = ttk.Entry(self.sett_frame, width=60)
        self.api_entry.pack(padx=10, pady=5)
        self.save_api_btn = ttk.Button(self.sett_frame, text="💾 Сохранить", command=self.save_api_key)
        self.save_api_btn.pack(padx=10, pady=5)

        self.settings = self.load_settings()
        self.api_entry.insert(0, self.settings.get('virustotal_api_key', ''))

        # Таблицы
        self.proc_table = self.create_table(self.proc_frame)
        self.auto_table = self.create_table(self.auto_frame)
        self.start_table = self.create_table(self.start_frame)
        self.sched_table = self.create_table(self.sched_frame)
        self.wmi_table = self.create_table(self.wmi_frame)
        self.serv_table = self.create_table(self.serv_frame)

        self.selected_proc = None
        self.proc_listbox = tk.Listbox(self.root, height=5)
        self.proc_listbox.pack(side='bottom', fill='x', padx=10, pady=5)
        self.proc_listbox.bind('<<ListboxSelect>>', self.on_select_process)

        self.refresh_all()

    def create_table(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill='both', expand=True)
        pt = Table(frame, showtoolbar=False, showstatusbar=True)
        pt.show()
        return pt

    def refresh_all(self):
        self.selected_proc = None
        self.proc_listbox.delete(0, tk.END)

        # Обновление данных
        processes = scan_suspicious_processes()
        autoruns = collect_autoruns_registry()
        startups = collect_startup_folders()
        scheduled = collect_scheduled_tasks_full()
        wmi_tasks = collect_wmi_tasks()
        services = collect_services()

        # Обновление таблиц
        self.proc_table.model.df = pd.DataFrame(processes)
        self.proc_table.redraw()

        self.auto_table.model.df = pd.DataFrame(autoruns)
        self.auto_table.redraw()

        self.start_table.model.df = pd.DataFrame(startups)
        self.start_table.redraw()

        self.sched_table.model.df = pd.DataFrame(scheduled)
        self.sched_table.redraw()

        self.wmi_table.model.df = pd.DataFrame(wmi_tasks)
        self.wmi_table.redraw()

        self.serv_table.model.df = pd.DataFrame(services)
        self.serv_table.redraw()

        # Список для действий
        for p in processes:
            self.proc_listbox.insert(tk.END, f"[{p['PID']}] {p['Имя']} | {p['Причины']}")

        # Сохранение отчета
        json.dump({
            'script_processes': find_script_processes(),
            'suspicious_processes': processes,
            'autoruns_registry': autoruns,
            'startup_folders': startups,
            'scheduled_tasks': scheduled,
            'wmi': wmi_tasks,
            'services': services
        }, open(REPORT_FILE, 'w', encoding='utf-8'), indent=2, ensure_ascii=False)

    def save_api_key(self):
        key = self.api_entry.get().strip()
        self.settings['virustotal_api_key'] = key
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.settings, f, indent=2, ensure_ascii=False)
        messagebox.showinfo("✅", "API ключ сохранён")

    def load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def on_select_process(self, event):
        idx = self.proc_listbox.curselection()
        if not idx:
            return
        pid_str = self.proc_listbox.get(idx).split(']')[0][1:]
        try:
            pid = int(pid_str)
            self.selected_proc = psutil.Process(pid)
        except Exception:
            self.selected_proc = None

    def check_admin(self):
        if not is_admin():
            messagebox.showerror("Ошибка", "Программа должна быть запущена от имени администратора!")
            self.root.destroy()

# ========================== MAIN ==============================
if __name__ == '__main__':
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        messagebox.showerror("Ошибка", "Запустите программу от имени администратора.")
        exit()

    root = tk.Tk()
    app = TaskSpyGUI(root)
    root.mainloop()
