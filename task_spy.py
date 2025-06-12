import os
import psutil
import subprocess
from datetime import datetime
from tabulate import tabulate
from colorama import Fore, Style, init
import json

init(autoreset=True)

REPORT_FILE = 'task_spy_report.json'
TARGET_EXTENSIONS = ['.py', '.bat', '.ps1']


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
    lines = result.stdout.splitlines()[3:]  # Пропустить заголовки
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


def save_report(suspects, scheduled):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report = {
        'timestamp': now,
        'processes': suspects,
        'scheduled': scheduled
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


def main():
    print(Fore.CYAN + "👁‍🗨 Task Spy: Поиск скриптов-процессов и задач планировщика\n")

    suspects = find_suspects()
    scheduled = get_scheduler_tasks()

    print_suspects(suspects)

    if scheduled:
        print(Fore.YELLOW + "\n[НАЙДЕНЫ ЗАДАЧИ ПЛАНИРОВЩИКА]")
        for task in scheduled:
            print(Fore.WHITE + f"• {task}")
    else:
        print(Fore.GREEN + "Нет задач в планировщике, связанных со скриптами.")

    save_report(suspects, scheduled)
    interact_menu(suspects)


if __name__ == "__main__":
    main()
