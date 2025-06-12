import os
import re
import json
import hashlib
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

VIRUSTOTAL_API_KEY = ''  # ← Опционально вставь свой API-ключ
REPORT_FILE = 'task_spy_report_final.json'
TARGET_EXTENSIONS = ['.py', '.bat', '.ps1']
SUSPICIOUS_NAMES = ['svshost', 'chrome_update', 'winlogin', 'serviceshost']
SUSPICIOUS_LOCATIONS = ['\\appdata\\', '\\temp\\', '\\programdata\\']
SUSPICIOUS_EXTENSIONS = ['.pif', '.scr', '.com', '.dat', '.cpl']

def hash_file(path):
    if not path or not os.path.isfile(path):
        return None
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

def find_scheduled_tasks():
    tasks = []
    try:
        result = subprocess.run(['schtasks'], capture_output=True, text=True, shell=True)
        for line in result.stdout.splitlines()[3:]:
            if any(ext in line.lower() for ext in TARGET_EXTENSIONS):
                tasks.append(line.strip())
    except Exception:
        pass
    return tasks

def is_suspicious_path(path): path = path.lower() if path else ''; return any(loc in path for loc in SUSPICIOUS_LOCATIONS)
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

def collect_autoruns():
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

def collect_services():
    return [{
        'name': svc.Name,
        'display': svc.DisplayName,
        'state': svc.State,
        'path': svc.PathName
    } for svc in wmi_conn.Win32_Service()
        if svc.StartMode == 'Auto' and svc.State == 'Running' and is_suspicious_name(svc.Name or '')]

def collect_wmi_tasks():
    try:
        return [{
            'Name': i.Name,
            'Command': i.Command,
            'User': i.User
        } for i in wmi_conn.Win32_StartupCommand()]
    except Exception: return []

def collect_drivers():
    return [{
        'Name': d.Name,
        'Display': d.DisplayName,
        'Path': d.PathName,
        'Description': d.Description
    } for d in wmi_conn.Win32_SystemDriver() if d.State == 'Running' and "Microsoft" not in (d.Description or "")]

def print_table(title, rows, headers):
    if not rows:
        print(Fore.GREEN + f"\n✔ {title}: ничего не найдено.")
    else:
        print(Fore.RED + f"\n📌 {title}:")
        print(tabulate(rows, headers=headers, tablefmt='fancy_grid'))

def show_processes_interactive(procs):
    if not procs:
        print(Fore.GREEN + "✔ Подозрительных процессов не найдено.\n")
        return
    print(Fore.RED + f"\n🦠 Найдено подозрительных процессов: {len(procs)}\n")
    while True:
        for idx, p in enumerate(procs):
            print(Fore.YELLOW + f"[{idx}] PID={p['pid']} | {p['name']}")
            print(Fore.WHITE + f"    Путь: {p['exe']}")
            print(f"    Аргументы: {p['cmdline']}")
            print(f"    Пользователь: {p['username']}")
            print(f"    Запущен: {p['started']}")
            print("    Причины:")
            for reason in p['reasons']:
                print(f"      → {reason}")
            print("-" * 60)
        choice = input(Fore.CYAN + "\nВыбери [номер] процесса или 'q' для выхода: ").strip()
        if choice.lower() == 'q':
            break
        if not choice.isdigit(): continue
        index = int(choice)
        if not (0 <= index < len(procs)): continue
        selected = procs[index]
        print(Fore.MAGENTA + f"\n▶ Выбран: PID {selected['pid']} | {selected['name']}")
        action = input(
            Fore.CYAN + "\nДействие:\n"
                        "v — Проверка в VirusTotal\n"
                        "k — Завершить процесс\n"
                        "s — Приостановить\n"
                        "[Enter] — ничего\n>>> ").lower().strip()
        if action == 'v':
            file_hash = hash_file(selected['exe'])
            vt_res = query_virustotal(file_hash)
            print(Fore.YELLOW + "Результат VirusTotal: " + vt_res)
        elif action == 'k':
            try: psutil.Process(selected["pid"]).terminate(); print(Fore.RED + "✔ Процесс завершён.")
            except Exception as e: print(f"Ошибка: {e}")
        elif action == 's':
            try: psutil.Process(selected["pid"]).suspend(); print(Fore.MAGENTA + "✔ Процесс приостановлен.")
            except Exception as e: print(f"Ошибка: {e}")

def main():
    print(Fore.CYAN + "👁‍🗨 Task Spy Pro — Финальная Версия\n")
    script_procs = find_script_processes()
    print_table("Запущенные скрипты", [
        [p['pid'], p['name'], p['cmdline'], p['username'], p['ppid']] for p in script_procs
    ], ["PID", "Имя", "Команда", "Пользователь", "PPID"])

    scheduler_tasks = find_scheduled_tasks()
    if scheduler_tasks:
        print(Fore.YELLOW + "\n📋 Планировщик задач:")
        for t in scheduler_tasks:
            print(f"  • {t}")
    else:
        print(Fore.GREEN + "\n✔ Задач в планировщике не обнаружено.")

    suspicious = scan_suspicious_processes()

    print_table("Автозапуск", [
        [a['source'], a['name'], a['command']] for a in collect_autoruns()
    ], ["Источник", "Имя", "Команда"])

    print_table("Службы", [
        [s['name'], s['display'], s['path']] for s in collect_services()
    ], ["System Name", "Display", "Path"])

    print_table("WMI Запуск", [
        [w['Name'], w['Command'], w['User']] for w in collect_wmi_tasks()
    ], ["Имя", "Команда", "Пользователь"])

    print_table("Драйверы", [
        [d['Name'], d['Display'], d['Description'], d['Path']] for d in collect_drivers()
    ], ["Имя", "Отображаемое", "Описание", "Путь"])

    show_processes_interactive(suspicious)

    json.dump({
        'script_processes': script_procs,
        'scheduler_tasks': scheduler_tasks,
        'suspicious_processes': suspicious,
        'autoruns': collect_autoruns(),
        'services': collect_services(),
        'wmi': collect_wmi_tasks(),
        'drivers': collect_drivers()
    }, open(REPORT_FILE, 'w', encoding='utf-8'), indent=2, ensure_ascii=False)

    print(Fore.CYAN + f"\n[✔] Отчёт сохранён: {REPORT_FILE}")

if __name__ == '__main__':
    main()
