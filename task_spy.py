import os
import json
import subprocess
import psutil
import requests
import wmi
import winreg
from datetime import datetime
from tabulate import tabulate
from colorama import Fore, init

init(autoreset=True)
wmi_conn = wmi.WMI()

# === Настройки ===
VIRUSTOTAL_API_KEY = ''  # ← Опционально вставьте ваш ключ
REPORT_FILE = 'task_spy_report_full.json'

TARGET_EXTENSIONS = ['.py', '.bat', '.ps1']
SUSPICIOUS_NAMES = ['svshost', 'chrome_update', 'winlogin', 'serviceshost']
SUSPICIOUS_LOCATIONS = ['\\appdata\\', '\\temp\\', '\\programdata\\']
SUSPICIOUS_EXTENSIONS = ['.pif', '.scr', '.com', '.dat', '.cpl']

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

def query_virustotal(file_hash):
    if not file_hash or not VIRUSTOTAL_API_KEY:
        return '—'
    try:
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return f"{stats['malicious']}/{sum(stats.values())} VT"
        return f"Ошибка {resp.status_code}"
    except Exception as e:
        return f"Ошибка VT: {e}"

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
            if is_suspicious_name(name): reasons.append("🕵 Подозрительное имя")
            if is_suspicious_ext(exe): reasons.append("📦 Подозрительное расширение")
            if info['ppid'] in (0, 4): reasons.append("🧬 Родитель PID 0/4")
            if "powershell" in cmdline.lower() and "-enc" in cmdline.lower(): reasons.append("🔐 Использует шифрование")
            if reasons:
                results.append({
                    'pid': info['pid'],
                    'name': name,
                    'exe': exe,
                    'cmdline': cmdline,
                    'username': info['username'],
                    'ppid': info['ppid'],
                    'started': datetime.fromtimestamp(info['create_time']).strftime('%Y-%m-%d %H:%M:%S'),
                    'reasons': reasons
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
                        'source': f"{'HKCU' if root == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{path}",
                        'name': name, 'command': val
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
                    'folder': folder,
                    'file': file,
                    'full_path': full_path
                })
    return entries

def collect_scheduled_tasks_full():
    tasks = []
    try:
        result = subprocess.run(["schtasks", "/query", "/fo", "LIST", "/v"], capture_output=True, text=True, shell=True)
        blocks = result.stdout.split("\n\n")
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
            'Name': i.Name,
            'Command': i.Command,
            'User': i.User
        } for i in wmi_conn.Win32_StartupCommand()]
    except Exception:
        return []

def collect_services():
    try:
        return [{
            'Name': x.Name,
            'DisplayName': x.DisplayName,
            'PathName': x.PathName
        } for x in wmi_conn.Win32_Service()
            if x.StartMode == "Auto" and x.State == "Running" and x.Name not in ("WinDefend",)]
    except Exception:
        return []

def print_table(title, rows, headers):
    print(Fore.CYAN + f"\n=== {title} ({len(rows)}) ===")
    if rows:
        print(tabulate(rows, headers, tablefmt='fancy_grid'))
    else:
        print(Fore.GREEN + "✔ Ничего не найдено.")

def show_processes(processes):
    if not processes:
        print(Fore.GREEN + "\n✔ Подозрительных процессов нет.")
        return
    for i, p in enumerate(processes):
        print(Fore.YELLOW + f"\n[{i}] PID={p['pid']} | {p['name']}")
        print(f"   Пользователь: {p['username']}")
        print(f"   Путь: {p['exe']}")
        print(f"   Аргументы: {p['cmdline']}")
        print(f"   Старт: {p['started']}")
        print("   Причины:")
        for r in p['reasons']:
            print(f"    → {r}")
        # Опционально: добавить проверку VirusTotal здесь

def main():
    print(Fore.MAGENTA + "🔍 Task Spy ULTIMATE — Полный просмотр автозагрузок Windows 🔍\n")

    scripts = find_script_processes()
    print_table("Запущенные скрипты", [
        [p['pid'], p['name'], p['cmdline'], p['username'], p['ppid']] for p in scripts
    ], ["PID", "Имя", "Команда", "Пользователь", "PPID"])

    suspicious = scan_suspicious_processes()
    show_processes(suspicious)

    print_table("🧬 Реестр автозагрузки", [
        [x['source'], x['name'], x['command']] for x in collect_autoruns_registry()
    ], ["Источник", "Имя", "Команда"])

    print_table("📂 Папки автозагрузки", [
        [x['folder'], x['file'], x['full_path']] for x in collect_startup_folders()
    ], ["Папка", "Файл", "Путь"])

    print_table("📋 Планировщик задач", [
        [t.get("TaskName", ""), t.get("Task To Run", ""), t.get("Status", ""), t.get("Last Run Time", "")] for t in collect_scheduled_tasks_full()
    ], ["Имя", "Команда", "Статус", "Последний запуск"])

    print_table("🤖 WMI автозапуск", [
        [x['Name'], x['Command'], x['User']] for x in collect_wmi_tasks()
    ], ["Имя", "Команда", "Пользователь"])

    print_table("⚙️ Службы (автозапуск)", [
        [x['Name'], x['DisplayName'], x['PathName']] for x in collect_services()
    ], ["Имя", "Отображаемое", "Путь"])

    json.dump({
        'script_processes': scripts,
        'suspicious_processes': suspicious,
        'autoruns_registry': collect_autoruns_registry(),
        'startup_folders': collect_startup_folders(),
        'scheduled_tasks': collect_scheduled_tasks_full(),
        'wmi': collect_wmi_tasks(),
        'services': collect_services()
    }, open(REPORT_FILE, 'w', encoding='utf-8'), indent=2, ensure_ascii=False)

    print(Fore.CYAN + f"\n[✔] Отчёт сохранён: {REPORT_FILE}")

if __name__ == '__main__':
    main()
