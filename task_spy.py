import os
import psutil
import subprocess
from datetime import datetime
from tabulate import tabulate
from colorama import Fore, Style, init
import json

# Цветной вывод
init(autoreset=True)

# Настройки
REPORT_FILE = 'task_spy_report.json'
TARGET_EXTENSIONS = ['.py', '.bat', '.ps1']
SUSPICIOUS_LOCATIONS = ['\\AppData\\', '\\Temp\\', '\\ProgramData\\']
SUSPICIOUS_NAMES = ['svshost', 'chrome_update', 'winlogin', 'systemhost', 'updatehost', 'spoolsvc']
SUSPICIOUS_EXTENSIONS = ['.pif', '.scr', '.com', '.cpl', '.dat']

# ---------- ФУНКЦИИ ----------

def find_suspects():
    suspects = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'ppid']):
        try:
            cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
            for ext in TARGET_EXTENSIONS:
                if ext in cmdline.lower():
                    suspects.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmd': cmdline,
                        'exe': proc.info['exe'],
                        'username': proc.info['username'],
                        'ppid': proc.info['ppid'],
                    })
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return suspects

def get_scheduler_tasks():
    result = subprocess.run(["schtasks"], capture_output=True, text=True, shell=True)
    lines = result.stdout.splitlines()[3:]
    scripts = []
    for line in lines:
        if any(ext in line.lower() for ext in TARGET_EXTENSIONS):
            scripts.append(line.strip())
    return scripts

def print_suspects(suspects):
    if not suspects:
        print(Fore.GREEN + "Нет запущенных подозрительных скриптов.")
        return

    headers = ["PID", "Имя", "Команда", "Запущен от", "PID Родителя"]
    table = [
        [p['pid'], p['name'], p['cmd'], p['username'], p['ppid']]
        for p in suspects
    ]
    print(Fore.YELLOW + "[ОТКРЫТЫЕ ПРОЦЕССЫ]\n")
    print(tabulate(table, headers=headers, tablefmt='fancy_grid'))

def save_report(suspects, scheduled, malware=None):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report = {
        'timestamp': now,
        'processes': suspects,
        'scheduled': scheduled,
        'malware_candidates': malware or []
    }
    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    print(Fore.CYAN + f"\n[✔] Отчет сохранён в {REPORT_FILE}")

def kill_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(3)
        print(Fore.RED + f"Процесс {pid} завершён.")
    except Exception as e:
        print(Fore.RED + f"Ошибка при завершении: {e}")

def suspend_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.suspend()
        print(Fore.MAGENTA + f"Процесс {pid} приостановлен.")
    except Exception as e:
        print(Fore.RED + f"Ошибка при остановке: {e}")

def interact_menu(suspects):
    if not suspects:
        return

    print(Fore.BLUE + "\nВыбери номер процесса для действия:")
    for i, proc in enumerate(suspects):
        print(f"{i}: PID {proc['pid']} | {proc['cmd'][:60]}")

    choice = input("\nНомер процесса ('q' для выхода): ").strip()
    if choice == 'q':
        return

    try:
        index = int(choice)
        target = suspects[index]
        action = input("1 - Завершить, 2 - Приостановить, Enter - ничего: ").strip()
        if action == '1':
            kill_process(target['pid'])
        elif action == '2':
            suspend_process(target['pid'])
    except Exception as e:
        print(Fore.RED + f"Ошибка ввода: {e}")

# -------- НАШ АНТИВИРУСНЫЙ РЕЖИМ --------

def is_suspicious_path(path):
    if not path:
        return False
    path_lower = path.lower()
    return any(sub in path_lower for sub in SUSPICIOUS_LOCATIONS)

def is_suspicious_name(name):
    name = (name or '').lower()
    return any(fake in name for fake in SUSPICIOUS_NAMES)

def is_suspicious_ext(path):
    return any(path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)

def get_process_name(pid):
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "N/A"

def find_malware_candidates():
    suspects = []
    for proc in psutil.process_iter(attrs=['pid', 'name', 'exe', 'cmdline', 'username', 'ppid', 'create_time']):
        reasons = []
        try:
            name = proc.info['name'] or ''
            exe = proc.info['exe'] or ''
            cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
            ppid = proc.info['ppid']
            username = proc.info['username']

            if is_suspicious_path(exe):
                reasons.append("📁 Подозрительное расположение")
            if is_suspicious_name(name):
                reasons.append("🕵️ Похоже на фальшивое имя системы")
            if is_suspicious_ext(exe):
                reasons.append("📦 Необычное расширение")
            if ppid in (0, 4):
                reasons.append("🧬 Родитель PID подозрительный")

            if reasons:
                suspects.append({
                    'pid': proc.info['pid'],
                    'name': name,
                    'exe': exe,
                    'cmdline': cmdline,
                    'username': username,
                    'ppid': ppid,
                    'ppname': get_process_name(ppid),
                    'start_time': datetime.fromtimestamp(proc.info['create_time']).strftime("%Y-%m-%d %H:%M:%S") if proc.info.get('create_time') else 'n/a',
                    'reasons': reasons
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
            continue
    return suspects

def print_malware_section(candidates):
    print("\n" + Fore.RED + "═" * 70)
    print(Fore.RED + "        ПОДОЗРИТЕЛЬНЫЕ ПРОЦЕССЫ (malware-режим)")
    print("═" * 70)

    if not candidates:
        print(Fore.GREEN + "Ни одного подозрительного процесса не найдено.")
        return

    headers = ["#", "PID", "Имя", "Путь", "Род. PID", "Род. Имя", "Пользователь", "Время", "Причины"]
    table = []
    for idx, proc in enumerate(candidates):
        reasons_summary = "\n".join(proc['reasons'])
        table.append([
            idx,
            proc['pid'],
            proc['name'] or "—",
            proc['exe'] or "—",
            proc['ppid'],
            proc['ppname'],
            proc['username'] or "—",
            proc['start_time'],
            reasons_summary
        ])

    print(tabulate(table, headers=headers, tablefmt='fancy_grid'))

    interact_malware_menu(candidates)

def interact_malware_menu(candidates):
    try:
        index = input(Fore.CYAN + "\nВыбери # процесса для действий (или q): ")
        if index.lower() == "q" or not index:
            return
        idx = int(index)
        target = candidates[idx]
        print(Fore.MAGENTA + f"\n▶ Процесс выбран:  PID={target['pid']} ({target['name']})")
        print(Fore.LIGHTBLACK_EX + f"Путь: {target['exe']}")
        print(Fore.LIGHTBLACK_EX + f"Command Line: {target['cmdline']}")
        print(Fore.LIGHTBLACK_EX + f"Пользователь: {target['username']}")
        print(Fore.LIGHTBLACK_EX + f"Время запуска: {target['start_time']}")
        print(Fore.LIGHTBLACK_EX + f"Причины:\n - " + '\n - '.join(target['reasons']))

        action = input(Fore.CYAN + "\n1 - Завершить, 2 - Приостановить, Enter - ничего: ").strip()
        if action == '1':
            kill_process(target['pid'])
        elif action == '2':
            suspend_process(target['pid'])

    except Exception as e:
        print(Fore.RED + f"Ошибка: {e}")

# -------- MAIN --------

def main():
    print(Fore.CYAN + "👁‍🗨 Task Spy: Монитор задач и поиск подозрительных процессов\n")

    suspects = find_suspects()
    scheduled = get_scheduler_tasks()

    print_suspects(suspects)

    if scheduled:
        print(Fore.YELLOW + "\n[НАЙДЕНЫ ЗАДАЧИ ПЛАНИРОВЩИКА]")
        for task in scheduled:
            print(Fore.WHITE + f"• {task}")
    else:
        print(Fore.GREEN + "Нет задач в планировщике, связанных со скриптами.")

    malware_candidates = find_malware_candidates()
    print_malware_section(malware_candidates)
    save_report(suspects, scheduled, malware_candidates)
    interact_menu(suspects)

if __name__ == "__main__":
    main()
