#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import threading
import ipaddress # Используем для более надежной проверки приватных IP
import subprocess # Для выполнения команды ping
import re # Для извлечения времени пинга
import platform # Для определения ОС для команды ping
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# Попытка импортировать зависимости
try:
    import requests
    from colorama import init, Fore, Style
except ImportError:
    print("Ошибка: Не найдены необходимые библиотеки.")
    print("Пожалуйста, установите их, выполнив команду в терминале:")
    print("pip3 install requests colorama")
    # Или: python3 -m pip install requests colorama
    sys.exit(1)

# --- Константы ---
CONFIG_FILE = Path("config.json")
DEFAULT_CONFIG = {
    "thread": 50,
    "timeout": 10, # Таймаут для HTTP-запросов (сек)
    "max_ms": 5000, # Макс. задержка ответа хоста (мс) для попадания в good_proxies.txt
    "import": ["proxies.txt"],
    "export": "good_proxies.txt",
    # URL для проверки доступности и первоначальной задержки через прокси
    "host_check_url": "https://www.google.com",
    # URL для проверки IP-адреса, видимого через прокси
    "ip_check_url": "https://api.ipify.org?format=json",
    # --- Новые параметры ---
    "enable_ping": True, # Включить проверку пинга до IP прокси?
    "ping_timeout_ms": 1000, # Таймаут для одного пакета пинга (мс)
    "enable_speed_test": False, # Включить тест скорости скачивания?
    # URL для скачивания тестового файла (выберите стабильный источник)
    "speed_test_url": "http://speedtest.tele2.net/1MB.zip",
    # Минимальная скорость (KB/s) для вывода зеленым цветом (информативно, не влияет на запись в файл)
    "speed_min_good_kbps": 100
}

# --- Глобальные переменные и блокировки ---
checked_count = 0
proxies_length = 0
good_proxies_count = 0
lock = threading.Lock()

# --- Функции ---

def create_default_config():
    """Создает config.json с настройками по умолчанию, если он не существует."""
    if not CONFIG_FILE.exists():
        print(f"Файл '{CONFIG_FILE}' не найден. Создаю файл с настройками по умолчанию...")
        try:
            config_to_write = DEFAULT_CONFIG.copy()
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config_to_write, f, indent=4, ensure_ascii=False)
            print(f"Файл '{CONFIG_FILE}' создан. Пожалуйста, проверьте настройки (особенно speed_test_url) и запустите скрипт снова.")
        except IOError as e:
            print(f"{Fore.RED}Ошибка при создании файла конфигурации: {e}{Style.RESET_ALL}")
        sys.exit(1)

def load_config():
    """Загружает конфигурацию из JSON файла, добавляя недостающие ключи из дефолтного."""
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
            updated = False
            for key, value in DEFAULT_CONFIG.items():
                if key not in config:
                    print(f"{Fore.YELLOW}Предупреждение: Ключ '{key}' отсутствует в {CONFIG_FILE}. Используется значение по умолчанию: {value}{Style.RESET_ALL}")
                    config[key] = value
                    updated = True
            return config
    except json.JSONDecodeError as e:
        print(f"{Fore.RED}Ошибка: Некорректный формат файла '{CONFIG_FILE}'. {e}{Style.RESET_ALL}")
        sys.exit(1)
    except IOError as e:
        print(f"{Fore.RED}Ошибка при чтении файла конфигурации '{CONFIG_FILE}': {e}{Style.RESET_ALL}")
        sys.exit(1)

def load_proxies(import_files):
    """Загружает список прокси из указанных файлов."""
    proxies = set() # Используем set для автоматического удаления дубликатов
    for file_path_str in import_files:
        file_path = Path(file_path_str)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    cleaned_line = line.strip()
                    if cleaned_line and ':' in cleaned_line: # Простая проверка формата
                        proxies.add(cleaned_line)
        except FileNotFoundError:
            print(f"{Fore.RED}Ошибка: Файл для импорта '{file_path}' не найден.{Style.RESET_ALL}")
        except IOError as e:
            print(f"{Fore.RED}Ошибка при чтении файла '{file_path}': {e}{Style.RESET_ALL}")
    return list(proxies) # Возвращаем список

def is_private_ip(ip_str):
    """Проверяет, является ли IP-адрес приватным (RFC 1918) или локальным."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        return False

def ping_host(ip_address, timeout_ms=1000):
    """Пингует IP-адрес и возвращает задержку в мс или None при ошибке/таймауте."""
    try:
        timeout_sec = timeout_ms / 1000.0
        current_os = platform.system().lower()
        if current_os == "windows":
            command = ["ping", "-n", "1", "-w", str(timeout_ms), ip_address]
            # В Windows пинг может требовать прав администратора для некоторых опций или в некоторых сетях.
            # startupinfo используется для скрытия окна консоли ping
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            creationflags = subprocess.CREATE_NO_WINDOW
        else: # Linux, macOS, etc.
            command = ["ping", "-c", "1", "-W", str(timeout_sec), ip_address]
            startupinfo = None
            creationflags = 0

        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout_sec + 0.5,
                                startupinfo=startupinfo, creationflags=creationflags, check=False) # check=False чтобы не вызывать исключение при returncode != 0

        if result.returncode == 0:
            match = re.search(r"time[=<]([\d.]+)\s?ms", result.stdout, re.IGNORECASE)
            if match:
                return int(float(match.group(1)))
            match_avg = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", result.stdout) # Linux
            if match_avg:
                 return int(float(match_avg.group(1)))
            match_round_trip = re.search(r"round-trip min/avg/max/stddev = [\d.]+/([\d.]+)/", result.stdout) # macOS?
            if match_round_trip:
                 return int(float(match_round_trip.group(1)))
            # Если ничего не нашли, но код возврата 0 (успех), вернем 0 мс? Или None?
            # print(f"Пинг {ip_address} успешен, но не удалось извлечь время:\n{result.stdout}")
            return None
        else:
            # print(f"Пинг {ip_address} не прошел, код: {result.returncode}, вывод:\n{result.stderr or result.stdout}")
            return None
    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError:
        print(f"{Fore.RED}Ошибка: Команда 'ping' не найдена в системе.{Style.RESET_ALL}")
        # Отключим пинг глобально, если не найден
        config['enable_ping'] = False
        return None
    except Exception as e:
        # print(f"Ошибка при выполнении ping для {ip_address}: {e}") # Отладка
        return None

def test_download_speed(proxy_dict, url, timeout_sec=10):
    """Скачивает файл через прокси и возвращает скорость в KB/s или None."""
    start_time = time.time()
    bytes_downloaded = 0
    try:
        with requests.get(url, proxies=proxy_dict, stream=True, timeout=timeout_sec) as response:
            response.raise_for_status() # Проверяем HTTP ошибки
            for chunk in response.iter_content(chunk_size=8192): # 8KB chunk
                bytes_downloaded += len(chunk)
                # Добавим проверку таймаута внутри цикла скачивания
                if time.time() - start_time > timeout_sec:
                    raise requests.exceptions.Timeout("Download timeout during streaming")
            end_time = time.time()

        duration = end_time - start_time
        if duration > 0.001 and bytes_downloaded > 0: # Избегаем деления на ноль или около нуля
            speed_kbps = (bytes_downloaded / 1024) / duration
            return round(speed_kbps)
        else:
            return 0 # Скачали 0 байт или время слишком мало

    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.RequestException as e:
        return None
    except Exception as e:
        # print(f"Ошибка при тесте скорости для {proxy_dict}: {e}") # Отладка
        return None

def check_proxy(proxy_str, config, export_file_path):
    """Проверяет один прокси: IP, доступность, пинг, скорость."""
    # --- ИСПРАВЛЕНИЕ: Объявляем глобальные переменные в начале функции ---
    global checked_count, good_proxies_count
    # -------------------------------------------------------------------

    log_prefix = f"{Fore.WHITE}{proxy_str}{Style.RESET_ALL} |" # Начинаем с белого
    result_message = ""
    status_color = Fore.RED # По умолчанию - ошибка

    try:
        proxy_ip, proxy_port = proxy_str.split(':', 1)
        if not proxy_port.isdigit() or not (0 < int(proxy_port) < 65536):
            result_message = "Некорректный порт"
            raise ValueError("Invalid port") # Используем исключение для выхода в finally
    except ValueError:
        print(f"{log_prefix} {Fore.RED}{result_message or 'Некорректный формат (ожидается IP:PORT)'}{Style.RESET_ALL}")
        return # Выход из функции, не считаем как проверенный по сети

    # Формируем словарь для requests
    proxies_dict = {'http': f'http://{proxy_str}', 'https': f'http://{proxy_str}'}
    timeout_http = config['timeout']
    max_ms_host = config['max_ms']
    proxy_is_private = is_private_ip(proxy_ip)

    ping_result_ms = None
    speed_result_kbps = None
    host_latency_ms = None
    is_good = False # Флаг, что прокси прошел базовые проверки

    try:
        # 1. Проверка IP (если не приватный)
        if not proxy_is_private:
            try:
                response_ip = requests.get(config['ip_check_url'], proxies=proxies_dict, timeout=timeout_http)
                response_ip.raise_for_status()
                seen_ip = response_ip.json()['ip']
                if seen_ip != proxy_ip:
                    result_message = f"IP не совпадает (ожидался {proxy_ip}, получен {seen_ip})"
                    raise ValueError("IP mismatch") # Выход из блока try
            except requests.exceptions.Timeout:
                result_message = f"Тайм-аут при проверке IP ({config['ip_check_url']})"
                raise ValueError("IP check timeout")
            except (requests.exceptions.RequestException, json.JSONDecodeError, KeyError) as e:
                result_message = f"Ошибка проверки IP: {type(e).__name__}"
                raise ValueError("IP check error")

        # 2. Проверка доступности хоста и задержки
        try:
            start_time = time.perf_counter()
            response_host = requests.head(config['host_check_url'], proxies=proxies_dict, timeout=timeout_http, allow_redirects=True)
            response_host.raise_for_status()
            end_time = time.perf_counter()
            host_latency_ms = round((end_time - start_time) * 1000)
        except requests.exceptions.Timeout:
            result_message = f"Тайм-аут при проверке хоста ({config['host_check_url']})"
            raise ValueError("Host check timeout")
        except requests.exceptions.RequestException as e:
            status_code_info = ""
            if hasattr(e, 'response') and e.response is not None:
                status_code_info = f" (Статус: {e.response.status_code})"
            result_message = f"Ошибка проверки хоста: {type(e).__name__}{status_code_info}"
            raise ValueError("Host check error")

        # --- Если дошли сюда, базовая проверка хоста пройдена ---
        is_good = True # Прокси как минимум отвечает

        # 3. Пинг (если включен)
        if config['enable_ping']:
            ping_result_ms = ping_host(proxy_ip, config['ping_timeout_ms'])

        # 4. Тест скорости (если включен)
        if config['enable_speed_test']:
            speed_timeout = max(timeout_http, 15) # Например, минимум 15 сек на скачивание
            speed_result_kbps = test_download_speed(proxies_dict, config['speed_test_url'], timeout_sec=speed_timeout)

        # --- Формирование итогового сообщения и статуса ---
        status_parts = []
        if host_latency_ms is not None:
            if host_latency_ms < max_ms_host:
                 status_parts.append(f"{Fore.GREEN}{host_latency_ms}ms{Style.RESET_ALL}")
                 status_color = Fore.GREEN # Основной критерий пройден
            else:
                 status_parts.append(f"{Fore.YELLOW}{host_latency_ms}ms{Style.RESET_ALL}")
                 status_color = Fore.YELLOW # Медленный, но рабочий

        if ping_result_ms is not None:
            status_parts.append(f"Ping: {ping_result_ms}ms")
        elif config['enable_ping']:
            status_parts.append(f"{Fore.YELLOW}Ping: N/A{Style.RESET_ALL}") # Если пинг был включен, но не удался

        if speed_result_kbps is not None:
             speed_color = Fore.GREEN if speed_result_kbps >= config['speed_min_good_kbps'] else Fore.YELLOW
             status_parts.append(f"Speed: {speed_color}{speed_result_kbps} KB/s{Style.RESET_ALL}")
        elif config['enable_speed_test']:
             status_parts.append(f"{Fore.YELLOW}Speed: N/A{Style.RESET_ALL}") # Если тест был включен, но не удался

        result_message = " | ".join(filter(None, status_parts)) # Собираем части сообщения

        # Запись в файл только если основной критерий (host_latency_ms < max_ms_host) выполнен
        if status_color == Fore.GREEN:
            with lock:
                try:
                    with open(export_file_path, 'a', encoding='utf-8') as export_f:
                        export_f.write(f'{proxy_str}\n')
                    good_proxies_count += 1 # Инкрементируем глобальную переменную
                except IOError as e:
                     print(f"{Fore.RED}Ошибка записи в файл {export_file_path}: {e}{Style.RESET_ALL}")


    except Exception as e:
        if not result_message: # Если сообщение не было установлено ранее
             result_message = f"Непредвиденная ошибка: {type(e).__name__} {e}"
        status_color = Fore.RED
        is_good = False

    finally:
        # Выводим итоговый лог для этого прокси
        print(f"{log_prefix} {status_color}{result_message}{Style.RESET_ALL}")

        # Обновляем счетчик обработанных и заголовок окна
        with lock:
            checked_count += 1 # Инкрементируем глобальную переменную
            # Чтение good_proxies_count здесь безопасно
            title = f"Proxy Checker | Обработано: {checked_count}/{proxies_length} | Рабочих: {good_proxies_count}"
            sys.stdout.write(f"\x1b]2;{title}\x07")
            sys.stdout.flush()

# --- Основная часть скрипта ---
if __name__ == "__main__":

    # Инициализация Colorama
    init()

    # Очистка экрана
    os.system('cls' if os.name == 'nt' else 'clear')

    # Проверка/создание/загрузка конфига
    create_default_config()
    config = load_config() # Загружаем конфиг, чтобы использовать его для отключения пинга при ошибке

    # Вывод баннера
    print(Fore.GREEN + r'''
___________ _______   ____   __  _____  _   _  _____ _____  _   __ ___________
| ___ \ ___ \  _  \ \ / /\ \ / / /  __ \| | | ||  ___/  __ \| | / /|  ___| ___ \
| |_/ / |_/ / | | |\ V /  \ V /  | /  \/| |_| || |__ | /  \/| |/ / | |__ | |_/ /
|  __/|    /| | | |/   \   \ /   | |    |  _  ||  __|| |    |    \ |  __||    /
| |   | |\ \\ \_/ / /^\ \  | |   | \__/\| | | || |___| \__/\| |\  \| |___| |\ \
\_|   \_| \_|\___/\/   \/  \_/    \____/\_| |_/\____/ \____/\_| \_/\____/\_| \_|
''' + Style.RESET_ALL)

    # Вывод настроек
    print(Fore.CYAN + "--- Настройки (из config.json) ---")
    print(f"    Потоки: {config['thread']}")
    print(f"    Тайм-аут HTTP (сек): {config['timeout']}")
    print(f"    Макс. задержка хоста (мс): {config['max_ms']}")
    print(f"    Файлы импорта: {', '.join(config['import'])}")
    print(f"    Файл экспорта: {config['export']}")
    print(f"    URL проверки хоста: {config['host_check_url']}")
    print(f"    URL проверки IP: {config['ip_check_url']}")
    print(f"    Пинг включен: {'Да' if config['enable_ping'] else 'Нет'}")
    if config['enable_ping']:
        print(f"      Тайм-аут пинга (мс): {config['ping_timeout_ms']}")
    print(f"    Тест скорости включен: {'Да' if config['enable_speed_test'] else 'Нет'}")
    if config['enable_speed_test']:
        print(f"      URL теста скорости: {config['speed_test_url']}")
        print(f"      Мин. скор. для OK (KB/s): {config['speed_min_good_kbps']}")
    print("-" * 35 + Style.RESET_ALL)

    # Загрузка прокси
    print(Fore.YELLOW + "Загрузка списка прокси..." + Style.RESET_ALL)
    proxies = load_proxies(config['import'])
    proxies_length = len(proxies)

    if proxies_length == 0:
        print(Fore.RED + "Ошибка: Не найдено ни одного прокси для проверки." + Style.RESET_ALL)
        sys.exit(1)

    # Подготовка файла экспорта
    export_file = Path(config['export'])
    try:
        with open(export_file, 'w', encoding='utf-8') as f:
            pass # Очищаем файл
        print(f"{Fore.CYAN}Файл экспорта '{export_file}' очищен/подготовлен.{Style.RESET_ALL}")
    except IOError as e:
        print(f"{Fore.RED}Ошибка при подготовке файла экспорта '{export_file}': {e}{Style.RESET_ALL}")
        sys.exit(1)

    # Запуск проверки
    print(Fore.CYAN + f"Начинаю проверку {proxies_length} прокси в {config['thread']} потоков..." + Style.RESET_ALL)
    start_run_time = time.time()
    initial_title = f"Proxy Checker | Проверка 0/{proxies_length} | Рабочих: 0"
    sys.stdout.write(f"\x1b]2;{initial_title}\x07")
    sys.stdout.flush()

    # Создаем пул потоков
    with ThreadPoolExecutor(max_workers=config['thread']) as executor:
        futures = [executor.submit(check_proxy, proxy, config, export_file) for proxy in proxies]

    # Завершение (shutdown по умолчанию ждет завершения всех задач)
    end_run_time = time.time()
    total_time = round(end_run_time - start_run_time)

    # Финальный вывод статистики
    print("\n" + Fore.GREEN + "=" * 40)
    print(f"Проверка завершена за {total_time} сек.")
    print(f"Всего обработано строк: {checked_count}")
    print(f"Найдено рабочих прокси (по критерию <{config['max_ms']}ms): {good_proxies_count}")
    print(f"Результаты сохранены в файл: {config['export']}")
    print("=" * 40 + Style.RESET_ALL)

    # Сброс заголовка окна
    sys.stdout.write('\x1b]2;Proxy Checker | Готово\x07')
    sys.stdout.flush()

    sys.exit(0)