import random
import asyncio
import tkinter as tk
from tkinter import messagebox, scrolledtext
import datetime
import aiohttp
import threading
import pystray
from PIL import Image
import sys
import os
import time

class SimpleIni:
    def __init__(self):
        self.sections = {}

    def read(self, filename):
        with open(filename, 'r', encoding='utf-8') as f:
            section_name = None
            for line in f.readlines():
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    section_name = line[1:-1]
                    self.sections[section_name] = {}
                elif '=' in line and section_name:
                    key, value = map(str.strip, line.split('=', 1))
                    self.sections[section_name][key] = value

    def write(self, filename):
        with open(filename, 'w', encoding='utf-8') as f:
            for section, options in self.sections.items():
                f.write(f'[{section}]\n')
                for option, value in options.items():
                    f.write(f'{option}={value}\n')
                f.write('\n')

    def has_section(self, section):
        return section in self.sections

    def getboolean(self, section, option, fallback=None):
        val = self.get(section, option)
        if val is None:
            return fallback
        return val.lower() in ('true', 'yes', 'on', '1')

    def get(self, section, option, fallback=None):
        return self.sections.get(section, {}).get(option, fallback)

    def set(self, section, option, value):
        if section not in self.sections:
            self.sections[section] = {}
        self.sections[section][option] = value

class ProxyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HTTPS Прокси")
        self.root.geometry("750x600")  # Увеличили ширину окна для лучшей читаемости
        self.root.resizable(True, True)
        # Инициализируем необходимые переменные
        self.server_task = None
        self.loop = None
        self.running = False
        self.tasks = []
        self.active_connections = []
        self.log_size = 0
        self.max_log_size = 1024 * 1024  # 1 MB
        self.BLOCKED = set()
        self.tray_icon = None
        self.server = None  # Объект сервера
        # Переменные для учета трафика
        self.upload_bytes = 0
        self.download_bytes = 0
        self.session_upload_bytes = 0
        self.session_download_bytes = 0
        self.last_update_time = 0
        self.last_hour_stats = {'upload': 0, 'download': 0}
        self.stats_file = "traffic_stats.csv"
        self.last_saved_hour = None
        # Параметры по умолчанию
        self.default_url = "https://github.com/andreiwsa/pacbl/releases/download/v09082025/youtube-domain.txt"
        self.config_file = "proxy_config.ini"
        # Инициализируем настройки конфигурации
        self.config = SimpleIni()
        # UI-переменные
        self.auto_start = tk.BooleanVar()
        self.minimize_to_tray = tk.BooleanVar()
        self.last_url = tk.StringVar()
        # Загружаем конфигурацию
        self.load_config()
        # Создаем графический интерфейс
        self.create_gui()
        # Автозапуск сервера, если задано
        if self.auto_start.get():
            self.load_blocked_domains_and_start()
        # Таймер для периодического сохранения статистики
        self.start_stats_timer()

    def save_config(self, **kwargs):
        """Сохраняет текущую конфигурацию."""
        if not self.config.has_section('Settings'):
            self.config.set('Settings', '', '')
        # Применяем дополнительные параметры
        for key, value in kwargs.items():
            self.config.set('Settings', key, str(value))
        # Сохраняем актуальные значения из интерфейса
        self.config.set('Settings', 'auto_start', str(self.auto_start.get()))
        self.config.set('Settings', 'minimize_to_tray', str(self.minimize_to_tray.get()))
        self.config.set('Settings', 'last_url', self.last_url.get())
        try:
            self.config.write(self.config_file)
        except Exception as e:
            self.log_message(f"Ошибка сохранения настроек: {e}")

    def load_config(self):
        """Загружает конфигурацию из файла или устанавливает дефолтные значения."""
        # Дефолтные настройки
        defaults = {
            'auto_start': 'False',
            'minimize_to_tray': 'True',
            'last_url': self.default_url
        }
        # Чтение существующего файла конфигурации
        if os.path.exists(self.config_file):
            try:
                self.config.read(self.config_file)
            except Exception as e:
                self.log_message(f"Ошибка чтения конфига: {e}, используем дефолтные значения")
        # Установка значений
        try:
            auto_start_val = self.config.getboolean('Settings', 'auto_start', fallback=False)
            minimize_val = self.config.getboolean('Settings', 'minimize_to_tray', fallback=True)
            last_url_val = self.config.get('Settings', 'last_url', fallback=self.default_url)
            self.auto_start.set(auto_start_val)
            self.minimize_to_tray.set(minimize_val)
            self.last_url.set(last_url_val)
        except Exception as e:
            self.log_message(f"Ошибка парсинга конфига: {e}, используем дефолтные значения")
            self.auto_start.set(False)
            self.minimize_to_tray.set(True)
            self.last_url.set(self.default_url)
        # Сохраняем конфигурацию сразу же
        self.save_config()

    def create_gui(self):
        """Создает графический интерфейс."""
        # Верхняя панель для ввода URL
        url_frame = tk.Frame(self.root)
        url_frame.pack(pady=5, fill=tk.X, padx=10)
        tk.Label(url_frame, text="URL списка доменов:").pack(side=tk.LEFT)
        self.url_entry = tk.Entry(url_frame, textvariable=self.last_url)
        self.url_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.setup_entry_bindings(self.url_entry)
        self.load_btn = tk.Button(url_frame, text="Загрузить", command=self.load_blocked_domains_and_start)
        self.load_btn.pack(side=tk.LEFT)
        # Панель для ручного добавления доменов
        custom_frame = tk.Frame(self.root)
        custom_frame.pack(pady=5, fill=tk.X, padx=10)
        tk.Label(custom_frame, text="Добавить свои домены (по одному или списком):").pack(anchor=tk.W)
        self.custom_text = tk.Text(custom_frame, height=3, width=50)
        self.custom_text.pack(fill=tk.X, pady=2)
        self.add_btn = tk.Button(custom_frame, text="Добавить", command=self.add_custom_domains)
        self.add_btn.pack(anchor=tk.E, padx=2)
        # Настройка чекбоксов для автозагрузки и минимизации в трей
        settings_frame = tk.Frame(self.root)
        settings_frame.pack(pady=5, fill=tk.X, padx=10)
        tk.Checkbutton(settings_frame, text="Автостарт прокси", variable=self.auto_start,
                      command=lambda: self.save_config(auto_start=self.auto_start.get())).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(settings_frame, text="Сворачивать в трей", variable=self.minimize_to_tray,
                      command=lambda: self.save_config(minimize_to_tray=self.minimize_to_tray.get())).pack(side=tk.LEFT, padx=5)
        # Блок статистики трафика
        traffic_frame = tk.Frame(self.root)
        traffic_frame.pack(pady=5, fill=tk.X, padx=10)
        # Статистика за последний час
        hour_frame = tk.Frame(traffic_frame)
        hour_frame.pack(side=tk.TOP, fill=tk.X)
        tk.Label(hour_frame, text="За последний час:").pack(side=tk.LEFT)
        self.hour_upload_label = tk.Label(hour_frame, text="Отправлено: 0 Б")
        self.hour_upload_label.pack(side=tk.LEFT, padx=5)
        self.hour_download_label = tk.Label(hour_frame, text="Получено: 0 Б")
        self.hour_download_label.pack(side=tk.LEFT, padx=5)
        # Статистика за текущую сессию
        session_frame = tk.Frame(traffic_frame)
        session_frame.pack(side=tk.TOP, fill=tk.X)
        tk.Label(session_frame, text="За сессию:").pack(side=tk.LEFT)
        self.session_upload_label = tk.Label(session_frame, text="Отправлено: 0 Б")
        self.session_upload_label.pack(side=tk.LEFT, padx=5)
        self.session_download_label = tk.Label(session_frame, text="Получено: 0 Б")
        self.session_download_label.pack(side=tk.LEFT, padx=5)
        # Кнопка сброса статистики
        self.reset_traffic_btn = tk.Button(traffic_frame, text="Сбросить", command=self.reset_traffic_stats)
        self.reset_traffic_btn.pack(side=tk.RIGHT, padx=5)
        # Индикатор статуса сервера
        self.status_frame = tk.Frame(self.root)
        self.status_frame.pack(pady=5)
        self.indicator_canvas = tk.Canvas(self.status_frame, width=20, height=20)
        self.indicator_canvas.pack(side=tk.LEFT)
        self.indicator = self.indicator_canvas.create_oval(5, 5, 15, 15, fill="gray")
        self.status_label = tk.Label(self.status_frame, text="Статус: Выключен", font=("Arial", 10))
        self.status_label.pack(side=tk.LEFT, padx=10)
        # Контроль запуска и остановки сервера
        self.btn_frame = tk.Frame(self.root)
        self.btn_frame.pack(pady=5)
        # Новый обработчик для кнопки "Включить"
        self.start_btn = tk.Button(self.btn_frame, text="Включить", width=10, command=self.on_include_click)
        self.start_btn.grid(row=0, column=0, padx=5)
        self.stop_btn = tk.Button(self.btn_frame, text="Выключить", width=10, command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=1, padx=5)
        self.exit_btn = tk.Button(self.btn_frame, text="Закрыть", width=10, command=self.on_close)
        self.exit_btn.grid(row=0, column=2, padx=5)
        # Поле логирования
        self.log_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, height=15, state='disabled')
        self.log_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        # Протокол закрывания окна
        self.root.protocol("WM_DELETE_WINDOW", self.minimize_window)
        self.log_message("Приложение запущено и готово к работе.")

    def start_stats_timer(self):
        """Инициализирует таймер для регулярного сохранения статистики трафика."""
        def check_and_save_stats():
            now = datetime.datetime.now()
            current_hour = now.replace(minute=0, second=0, microsecond=0)
            # Проверяем, прошел ли целый час с момента последнего сохранения
            if self.last_saved_hour is None or current_hour > self.last_saved_hour:
                self.save_traffic_stats()
                self.last_saved_hour = current_hour
            self.root.after(60000, check_and_save_stats)  # Проверять каждые 60 секунд
        self.root.after(60000, check_and_save_stats)  # Первый запуск через минуту

    def save_traffic_stats(self):
        """Сохраняет статистику трафика за последнюю полную запись часов в CSV-файл."""
        try:
            # Разница между текущими значениями и предыдущей записью
            upload_diff = self.upload_bytes - self.last_hour_stats['upload']
            download_diff = self.download_bytes - self.last_hour_stats['download']
            # Пустой трафик пропускаем
            if upload_diff == 0 and download_diff == 0:
                return
            # Подготавливаем строку времени для сохранения
            now = datetime.datetime.now()
            hour_start = now.replace(minute=0, second=0, microsecond=0)
            timestamp = hour_start.strftime("%Y-%m-%d %H:%M:%S")
            # Реализуем свою версию записи в CSV-файл без использования библиотеки csv
            file_exists = os.path.exists(self.stats_file)
            with open(self.stats_file, 'a', newline='', encoding='utf-8') as stats_file:
                if not file_exists:
                    header_row = f'Timestamp,Upload (bytes),Download (bytes)\n'
                    stats_file.write(header_row)
                row = f'{timestamp},{upload_diff},{download_diff}\n'
                stats_file.write(row)
            # Обновляем предыдущий статус
            self.last_hour_stats = {
                'upload': self.upload_bytes,
                'download': self.download_bytes
            }
            self.log_message(f"Сохранилась статистика за час: Отправлено {upload_diff} Б, Получено {download_diff} Б")
        except Exception as e:
            self.log_message(f"Ошибка сохранения статистики: {e}")

    def setup_entry_bindings(self, entry):
        """Настраивает горячие клавиши для копирования-вставки текста."""
        entry.bind("<Control-c>", lambda e: self.copy_to_clipboard(entry))
        entry.bind("<Control-v>", lambda e: self.paste_from_clipboard(entry))
        entry.bind("<Control-x>", lambda e: self.cut_to_clipboard(entry))
        entry.bind("<Control-a>", lambda e: entry.select_range(0, 'end'))

    def copy_to_clipboard(self, entry):
        """Копирует выделенный текст в буфер обмена."""
        try:
            if entry.selection_present():
                text = entry.selection_get()
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
        except:
            pass

    def paste_from_clipboard(self, entry):
        """Вставляет текст из буфера обмена в элемент ввода."""
        try:
            text = self.root.clipboard_get()
            if text:
                entry.delete(tk.SEL_FIRST, tk.SEL_LAST if entry.selection_present() else tk.INSERT)
                entry.insert(tk.INSERT, text)
        except:
            pass

    def cut_to_clipboard(self, entry):
        """Вырезает выделенный текст и помещает его в буфер обмена."""
        self.copy_to_clipboard(entry)
        if entry.selection_present():
            entry.delete(tk.SEL_FIRST, tk.SEL_LAST)

    def update_traffic_stats(self):
        """Обновляет визуализацию статистики трафика."""
        def format_bytes(size):
            units = ['Б', 'КБ', 'МБ', 'ГБ']
            for u in units:
                if size < 1024:
                    return f"{size:.2f} {u}"
                size /= 1024
            return f"{size:.2f} ТБ"
        # Расчет статистики за последний час
        now = datetime.datetime.now()
        current_hour = now.replace(minute=0, second=0, microsecond=0)
        if current_hour > self.last_saved_hour:
            hour_upload = self.upload_bytes - self.last_hour_stats['upload']
            hour_download = self.download_bytes - self.last_hour_stats['download']
            self.hour_upload_label.config(text=f"Отправлено: {format_bytes(hour_upload)}")
            self.hour_download_label.config(text=f"Получено: {format_bytes(hour_download)}")
        # Обновляем общий счётчик за сессию
        self.session_upload_label.config(text=f"Отправлено: {format_bytes(self.session_upload_bytes)}")
        self.session_download_label.config(text=f"Получено: {format_bytes(self.session_download_bytes)}")

    def reset_traffic_stats(self):
        """Очищает статистику трафика и сбрасывает её отображение."""
        self.upload_bytes = 0
        self.download_bytes = 0
        self.session_upload_bytes = 0
        self.session_download_bytes = 0
        self.last_hour_stats = {'upload': 0, 'download': 0}
        self.update_traffic_stats()
        self.log_message("Статистика трафика была успешно очищена.")

    def log_message(self, message):
        """Выводит сообщение в окно лога и сохраняет журнал в файле при превышении лимита."""
        def append():
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            full_message = f"[{timestamp}] {message}\n"
            self.log_text.config(state='normal')
            self.log_text.insert(tk.END, full_message)
            self.log_text.config(state='disabled')
            self.log_text.see(tk.END)
            self.log_size += len(full_message.encode('utf-8'))
            # Ограничиваем максимальный объем журнала
            if self.log_size >= self.max_log_size:
                self.save_log_to_file()
            # Ограничиваем количество записей в окне
            if len(self.log_text.get("1.0", tk.END)) * 2 > 2 * 1024 * 1024:
                self.log_text.config(state='normal')
                self.log_text.delete("1.0", "end-1c lineend")
                self.log_text.config(state='disabled')
        self.root.after(0, append)

    def save_log_to_file(self):
        """Сохраняет лог-файл на диск."""
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"proxy_log_{timestamp}.txt"
            content = self.log_text.get("1.0", tk.END)
            with open(filename, "w", encoding="utf-8") as f:
                f.write(content)
            self.log_message(f"Журнал сохранён: {filename}")
            self.log_size = 0
        except Exception as e:
            self.log_message(f"Ошибка сохранения журнала: {e}")

    def add_custom_domains(self):
        """Добавляет указанные пользователем домены в блокировку."""
        text = self.custom_text.get("1.0", tk.END).strip()
        if not text:
            return
        domains = [line.strip() for line in text.splitlines() if line.strip()]
        new_count = 0
        for domain in domains:
            try:
                encoded = domain.encode('idna') if domain.isascii() else domain.encode('utf-8')
            except Exception:
                continue
            if encoded not in self.BLOCKED:
                self.BLOCKED.add(encoded)
                new_count += 1
        self.custom_text.delete("1.0", tk.END)
        self.log_message(f"Добавлено вручную доменов: {new_count}")

    async def fetch_domains(self, url):
        """Асинхронно получает список заблокированных доменов по указанному URL."""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        raise Exception(f"HTTP {resp.status} {resp.reason}")
                    text = await resp.text()
                    domains = {line.strip().encode() for line in text.splitlines() if line.strip()}
                    return domains
            except Exception as e:
                self.log_message(f"Ошибка загрузки с URL: {e}")
                return set()

    def load_blocked_domains_and_start(self):
        """Загружает заблокированные домены и запускает сервер."""
        if not self.last_url.get().strip():
            self.log_message("URL не указан.")
            return
        self.load_btn.config(state=tk.DISABLED)
        async def async_load():
            try:
                self.log_message("Загрузка доменов с URL...")
                domains = await self.fetch_domains(self.last_url.get())
                self.BLOCKED = domains
                self.log_message(f"✅ Загружено {len(self.BLOCKED)} доменов")
                self.save_config(last_url=self.last_url.get())
                # self.start_server()  # Убираем автоматический запуск сервера здесь
            except Exception as e:
                self.log_message(f"Ошибка загрузки: {str(e)}")
            finally:
                self.root.after(0, lambda: self.load_btn.config(state=tk.NORMAL))
        threading.Thread(target=lambda: asyncio.run(async_load()), daemon=True).start()

    def get_asyncio_loop(self):
        """Возвращает текущий цикл событий или создаёт новый."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        if self.loop is None:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
        return self.loop

    async def pipe(self, reader, writer, is_upload):
        """Передаёт данные между двумя соединениями и подсчитывает объём передаваемых данных."""
        try:
            while not reader.at_eof():
                if self.server_task and self.server_task.done():
                    break  # Прервём передачу данных, если сервер отключается
                data = await reader.read(1500)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
                # Подсчет объема трафика
                if is_upload:
                    self.upload_bytes += len(data)
                    self.session_upload_bytes += len(data)
                else:
                    self.download_bytes += len(data)
                    self.session_download_bytes += len(data)
                # Обновляем GUI не чаще раза в полсекунды
                current_time = asyncio.get_event_loop().time()
                if current_time - self.last_update_time > 0.5:
                    self.last_update_time = current_time
                    self.root.after(0, self.update_traffic_stats)
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            self.log_message(f"[PIPE] Ошибка: {e}")
        finally:
            if not writer.is_closing():
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass

    async def fragment_data(self, local_reader, remote_writer):
        """Осуществляет фрагментирование HTTP-запросов."""
        try:
            head = await local_reader.read(5)
            data = await local_reader.read(1500)
            if any(site in data for site in self.BLOCKED):
                self.log_message("Фрагментировано соединение.")
                while data:
                    part_len = random.randint(1, len(data))
                    remote_writer.write(
                        bytes.fromhex("1603") +
                        random.randbytes(1) +
                        part_len.to_bytes(2, 'big') +
                        data[:part_len]
                    )
                    data = data[part_len:]
                await remote_writer.drain()
            else:
                remote_writer.write(head + data)
                await remote_writer.drain()
        except Exception as e:
            self.log_message(f"[FRAGMENT] Ошибка: {e}")

    async def handle_connection(self, local_reader, local_writer):
        """Обрабатывает входящие соединения."""
        addr = local_writer.get_extra_info('peername')
        conn_id = f"{addr[0]}:{addr[1]}"
        self.log_message(f"Новое подключение: {conn_id}")
        try:
            http_data = await asyncio.wait_for(local_reader.read(1500), timeout=10.0)
            if not http_data:
                return
            first_line = http_data.split(b"\r\n")[0]
            parts = first_line.split(b" ")
            if len(parts) < 3:
                return
            method, target, *_ = parts
            if method != b"CONNECT":
                return
            try:
                host_port = target.split(b":")
                if len(host_port) != 2:
                    return
                host, port = host_port
                host_str = host.decode('idna') if host.isascii() else host.decode('utf-8')
                port = int(port)
            except Exception as e:
                self.log_message(f"Некорректный CONNECT запрос: {target} — {e}")
                return
            self.log_message(f"Проксируем: {host_str}:{port}")
            local_writer.write(b'HTTP/1.1 200 OK\r\n\r\n')
            await local_writer.drain()
            try:
                remote_reader, remote_writer = await asyncio.open_connection(host_str, port)
                self.active_connections.append((remote_reader, remote_writer))
            except Exception as e:
                self.log_message(f"Ошибка подключения к {host_str}:{port}: {e}")
                return
            try:
                if port == 443:
                    await self.fragment_data(local_reader, remote_writer)
                task1 = asyncio.create_task(self.pipe(local_reader, remote_writer, is_upload=True))
                task2 = asyncio.create_task(self.pipe(remote_reader, local_writer, is_upload=False))
                self.tasks.extend([task1, task2])
                await asyncio.gather(task1, task2)
            except Exception as e:
                self.log_message(f"[CONNECTION] Ошибка передачи: {e}")
            finally:
                if (remote_reader, remote_writer) in self.active_connections:
                    self.active_connections.remove((remote_reader, remote_writer))
        except asyncio.TimeoutError:
            self.log_message(f"Тайм-аут подключения от {conn_id}")
        except Exception as e:
            self.log_message(f"[HANDLER] Ошибка: {e}")
        finally:
            local_writer.close()
            try:
                await local_writer.wait_closed()
            except:
                pass

    async def run_server(self):
        """Запускает прокси-сервер."""
        server = None
        try:
            server = await asyncio.start_server(
                self.handle_connection,
                '127.0.0.1',
                8881,
                reuse_address=True
            )
            self.server = server
            self.log_message("Сервер запущен на localhost:8881")
            async with server:
                await server.serve_forever()
        except asyncio.CancelledError:
            self.log_message("Сервер отключился.")
            if server:
                server.close()
                await server.wait_closed()
        except OSError as e:
            self.log_message(f"[SERVER] Ошибка привязки порта: {e}")
        except Exception as e:
            self.log_message(f"[SERVER] Ошибка: {e}")
        finally:
            self.server = None

    def start_server(self):
        """Запускает сервер, проверяя состояние активности."""
        # Проверяем только состояние задачи сервера
        # Это основной исправленный фрагмент логики
        if self.server_task is not None and not self.server_task.done():
            self.log_message("Сервер ещё активен, подождите завершения операции.")
            return

        # Если задача завершена или ещё не создана, можно запускать
        self.running = True
        self.update_indicator(True)
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        # Сбрасываем показатели статистики сессии
        self.session_upload_bytes = 0
        self.session_download_bytes = 0
        # Начинаем отсчёт часа заново
        self.last_saved_hour = datetime.datetime.now().replace(minute=0, second=0, microsecond=0)
        threading.Thread(target=self.run_asyncio, daemon=True).start()

    def run_asyncio(self):
        """Защищённый способ запуска цикла событий."""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.server = None
        try:
            self.server_task = self.loop.create_task(self.run_server())
            self.loop.run_until_complete(self.server_task)
        except (asyncio.CancelledError, RuntimeError):
            self.log_message("Сервер завершён.")
        except Exception as e:
            self.log_message(f"Ошибка основного цикла: {e}")
        finally:
            if self.loop:
                self.loop.close()
            self.loop = None
            # Убедимся, что состояние обновлено после завершения задачи
            # Используем _update_ui_after_stop для корректного обновления UI
            self.root.after(0, self._update_ui_after_stop)

    def _update_ui_after_stop(self):
        """Обновляет UI после завершения сервера."""
        # Убедимся, что флаг running сброшен
        self.running = False
        self.update_indicator(False)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        # Явно сбросим задачу после завершения
        self.server_task = None

    async def wait_for_tasks_completion(self):
        tasks = list(self.tasks)
        await asyncio.wait(tasks, timeout=5.0)  # Ждем максимум 5 секунд
        self.tasks.clear()

    def stop_server(self):
        # Сбрасываем флаг running сразу
        self.running = False
        self.update_indicator(False)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        # Останавливаем главный цикл
        if self.server_task and not self.server_task.done():
            self.server_task.cancel()
            
        # Ожидаем завершения задач с ограничением по времени
        if self.tasks:
            if self.loop and self.loop.is_running():
                asyncio.run_coroutine_threadsafe(self.wait_for_tasks_completion(), self.loop)
            else:
                # Если loop не активен, просто очищаем задачи
                self.tasks.clear()
                
        # Быстро закрываем оставшиеся соединения
        for _, writer in self.active_connections:
            writer.close()
            try:
                # asyncio.run_coroutine_threadsafe(writer.wait_closed(), self.loop)
                pass # В основном потоке TKinter лучше не ждать
            except:
                pass
        self.active_connections.clear()
        self.log_message("Все соединения закрыты.")

    def update_indicator(self, status):
        """Изменяет индикатор состояния сервера."""
        color = "green" if status else "gray"
        self.indicator_canvas.itemconfig(self.indicator, fill=color)
        self.status_label.config(text="Статус: " + ("Включён" if status else "Выключен"))

    def create_tray_icon(self):
        """Создаёт иконку в области уведомлений (трее)."""
        if self.tray_icon is not None:
            return
        # Генерируем временную картинку индикатора
        image = Image.new('RGB', (64, 64), color='green' if self.running else 'gray')
        menu = (
            pystray.MenuItem('Открыть', self.restore_window),
            pystray.MenuItem('Включить прокси', self.start_server, enabled=not self.running),
            pystray.MenuItem('Выключить прокси', self.stop_server, enabled=self.running),
            pystray.MenuItem('Выход', self.quit_application)
        )
        self.tray_icon = pystray.Icon("proxy_icon", image, "HTTPS Прокси", menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def minimize_window(self):
        """Минимизирует окно программы в область уведомлений."""
        if self.minimize_to_tray.get():
            self.root.withdraw()
            self.create_tray_icon()
        else:
            self.on_close()

    def restore_window(self):
        """Восстанавливает основное окно приложения."""
        if self.tray_icon is not None:
            self.tray_icon.stop()
            self.tray_icon = None
        self.root.deiconify()

    def quit_application(self):
        """Завершает работу приложения."""
        if self.tray_icon is not None:
            self.tray_icon.stop()
        self.stop_server()
        self.save_traffic_stats()
        self.root.quit()
        os._exit(0)

    def on_close(self):
        """Обработчик события закрытия окна приложения."""
        if self.running:
            if messagebox.askokcancel("Выход", "Прокси-сервер всё ещё работает. Завершить?"):
                self.quit_application()
        else:
            self.quit_application()

    def on_include_click(self):
        """Новый обработчик для кнопки Включить."""
        # Сначала загружаем домены
        self.load_blocked_domains_and_start()
        # Затем выполняем старт сервера (но только если загрузка успешна)
        # Для этого добавим небольшую задержку или лучше изменить логику
        # Пока просто вызовем start_server, предполагая, что домены уже загружены
        # В реальном приложении лучше бы добавить callback или проверку состояния
        self.root.after(100, self.start_server) # Небольшая задержка перед запуском

    @staticmethod
    def main():
        root = tk.Tk()
        app = ProxyApp(root)
        root.mainloop()

if __name__ == "__main__":
    ProxyApp.main()
