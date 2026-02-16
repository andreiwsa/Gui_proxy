import random
import asyncio
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog
import datetime
import aiohttp
import threading
import pystray
from PIL import Image, ImageDraw
import os
import re
import logging
from typing import Set, Optional, Dict, Any

# Настройка логгера
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ProxyApp")

class SimpleIni:
    """Реализация INI-файла."""
    def __init__(self):
        self.sections: Dict[str, Dict[str, str]] = {}

    def read(self, filename: str) -> None:
        try:
            if not os.path.exists(filename):
                return
            with open(filename, 'r', encoding='utf-8') as f:
                section_name = None
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if line.startswith('[') and line.endswith(']'):
                        section_name = line[1:-1]
                        self.sections.setdefault(section_name, {})
                    elif '=' in line and section_name:
                        key, value = map(str.strip, line.split('=', 1))
                        self.sections[section_name][key] = value
        except Exception as e:
            logger.error(f"Ошибка чтения конфигурации: {e}")

    def write(self, filename: str) -> None:
        try:
            temp_filename = filename + '.tmp'
            with open(temp_filename, 'w', encoding='utf-8') as f:
                for section, options in self.sections.items():
                    f.write(f'[{section}]\n')
                    for option, value in options.items():
                        f.write(f'{option}={value}\n')
                    f.write('\n')
            if os.path.exists(filename):
                os.replace(temp_filename, filename)
            else:
                os.rename(temp_filename, filename)
        except Exception as e:
            logger.error(f"Ошибка записи конфигурации: {e}")

    def has_section(self, section: str) -> bool:
        return section in self.sections

    def getboolean(self, section: str, option: str, fallback: Optional[bool] = None) -> bool:
        val = self.get(section, option)
        if val is None:
            return fallback if fallback is not None else False
        return val.lower() in ('true', 'yes', 'on', '1', 'y')

    def get(self, section: str, option: str, fallback: Optional[str] = None) -> Optional[str]:
        return self.sections.get(section, {}).get(option, fallback)

    def set(self, section: str, option: str, value: Any) -> None:
        if section not in self.sections:
            self.sections[section] = {}
        self.sections[section][option] = str(value)

class ProxyApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("HTTPS Прокси")
        self.root.geometry("850x750") 
        self.root.minsize(800, 700) 
        self.root.resizable(True, True)

        # Переменные
        self.server_task: Optional[asyncio.Task] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.running = False
        self.tasks: list = []
        self.active_connections: list = []
        self.BLOCKED: Set[bytes] = set()
        self.tray_icon = None
        self.server = None
        self._is_closing = False
        self._tray_ready = threading.Event()

        # Трафик
        self.upload_bytes = 0
        self.download_bytes = 0
        self.session_upload_bytes = 0
        self.session_download_bytes = 0
        self.last_update_time = 0
        self.last_hour_stats = {'upload': 0, 'download': 0}
        self.stats_file = "traffic_stats.csv"
        self.last_saved_hour = None

        # Настройки
        self.default_url = "https://github.com/andreiwsa/pacbl/releases/download/v09082025/youtube-domain.txt"
        self.config_file = "proxy_config.ini"
        self.config = SimpleIni()

        # UI-переменные
        self.auto_start = tk.BooleanVar(value=False)
        self.minimize_to_tray = tk.BooleanVar(value=True)
        self.last_url = tk.StringVar(value=self.default_url)
        self.loading_status = tk.StringVar(value="Готов")
        self.last_file_path = tk.StringVar(value="")

        self.load_config()
        self.create_gui()

        # Иконка в трее сразу при запуске
        self.root.after(500, self.create_tray_icon)

        if self.auto_start.get():
            self.root.after(100, self.load_blocked_domains_and_start)

        self.start_stats_timer()
        self.root.protocol("WM_DELETE_WINDOW", self.minimize_window)
        self.log_message("Приложение запущено. Иконка в трее активна.")

    def save_config(self, **kwargs) -> None:
        if self._is_closing: return
        try:
            if not self.config.has_section('Settings'):
                self.config.sections['Settings'] = {}
            for key, value in kwargs.items():
                self.config.set('Settings', key, str(value))
            self.config.set('Settings', 'auto_start', str(self.auto_start.get()))
            self.config.set('Settings', 'minimize_to_tray', str(self.minimize_to_tray.get()))
            self.config.set('Settings', 'last_url', self.last_url.get())
            self.config.set('Settings', 'last_file_path', self.last_file_path.get())
            self.config.write(self.config_file)
        except Exception as e:
            logger.error(f"Ошибка сохранения настроек: {e}")

    def load_config(self) -> None:
        self.config.read(self.config_file)
        try:
            self.auto_start.set(self.config.getboolean('Settings', 'auto_start', False))
            self.minimize_to_tray.set(self.config.getboolean('Settings', 'minimize_to_tray', True))
            url = self.config.get('Settings', 'last_url', self.default_url)
            if self.is_valid_url(url):
                self.last_url.set(url)
            else:
                self.last_url.set(self.default_url)
            
            file_path = self.config.get('Settings', 'last_file_path', "")
            if file_path and os.path.exists(file_path):
                self.last_file_path.set(f"Последний файл: {os.path.basename(file_path)}")
        except Exception as e:
            logger.error(f"Ошибка конфига: {e}")
        self.save_config()

    def is_valid_url(self, url: str) -> bool:
        url_pattern = re.compile(r'^(https?://)([a-zA-Z0-9.-]+)(:\d+)?(/[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=%-]*)*$', re.IGNORECASE)
        return bool(url_pattern.match(url))

    def create_gui(self) -> None:
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- Фрейм для URL ---
        url_frame = ttk.LabelFrame(main_frame, text="Настройки блокировки доменов")
        url_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(url_frame, text="URL списка доменов:").pack(anchor=tk.W, padx=5, pady=(5, 0))
        
        url_entry_frame = ttk.Frame(url_frame)
        url_entry_frame.pack(fill=tk.X, padx=5, pady=5)
        self.url_entry = ttk.Entry(url_entry_frame, textvariable=self.last_url)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.setup_entry_bindings(self.url_entry)
        
        self.load_btn = ttk.Button(url_entry_frame, text="Загрузить", command=self.load_blocked_domains_and_start)
        self.load_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Кнопка загрузки из файла
        file_frame = ttk.Frame(url_frame)
        file_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        self.load_file_btn = ttk.Button(file_frame, text="Загрузить из файла", command=self.load_domains_from_file)
        self.load_file_btn.pack(side=tk.LEFT)
        ttk.Label(file_frame, textvariable=self.last_file_path, foreground="gray").pack(side=tk.LEFT, padx=(10, 0))
        
        # Статус загрузки
        status_frame = ttk.Frame(url_frame)
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(status_frame, textvariable=self.loading_status, font=("Arial", 9, "italic")).pack(anchor=tk.W)

        # --- Ручное добавление ---
        custom_frame = ttk.LabelFrame(main_frame, text="Ручное добавление доменов")
        custom_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(custom_frame, text="Добавить домены (списком):").pack(anchor=tk.W, padx=5, pady=(5, 0))
        custom_text_frame = ttk.Frame(custom_frame)
        custom_text_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.custom_text = tk.Text(custom_text_frame, height=3)
        self.custom_text.pack(fill=tk.X, side=tk.LEFT, expand=True)
        scrollbar = ttk.Scrollbar(custom_text_frame, command=self.custom_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.custom_text['yscrollcommand'] = scrollbar.set
        
        self.add_btn = ttk.Button(custom_frame, text="Добавить", command=self.add_custom_domains)
        self.add_btn.pack(anchor=tk.E, padx=5, pady=5)

        # --- Настройки приложения ---
        settings_frame = ttk.LabelFrame(main_frame, text="Настройки приложения")
        settings_frame.pack(fill=tk.X, pady=(0, 10))
        
        settings_content = ttk.Frame(settings_frame)
        settings_content.pack(fill=tk.X, padx=5, pady=5)
        ttk.Checkbutton(settings_content, text="Автостарт прокси", variable=self.auto_start,
            command=lambda: self.save_config(auto_start=self.auto_start.get())).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Checkbutton(settings_content, text="Скрывать окно при закрытии", variable=self.minimize_to_tray,
            command=lambda: self.save_config(minimize_to_tray=self.minimize_to_tray.get())).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)

        # --- Статистика ---
        traffic_frame = ttk.LabelFrame(main_frame, text="Статистика трафика")
        traffic_frame.pack(fill=tk.X, pady=(0, 10))

        hour_frame = ttk.Frame(traffic_frame)
        hour_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(hour_frame, text="За последний час:").pack(side=tk.LEFT)
        self.hour_upload_label = ttk.Label(hour_frame, text="Отправлено: 0 Б")
        self.hour_upload_label.pack(side=tk.LEFT, padx=10)
        self.hour_download_label = ttk.Label(hour_frame, text="Получено: 0 Б")
        self.hour_download_label.pack(side=tk.LEFT)

        session_frame = ttk.Frame(traffic_frame)
        session_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(session_frame, text="За сессию:").pack(side=tk.LEFT)
        self.session_upload_label = ttk.Label(session_frame, text="Отправлено: 0 Б")
        self.session_upload_label.pack(side=tk.LEFT, padx=10)
        self.session_download_label = ttk.Label(session_frame, text="Получено: 0 Б")
        self.session_download_label.pack(side=tk.LEFT)

        self.reset_traffic_btn = ttk.Button(traffic_frame, text="Сбросить", command=self.reset_traffic_stats)
        self.reset_traffic_btn.pack(anchor=tk.E, padx=5, pady=5)

        # --- Индикатор статуса ---
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.indicator_canvas = tk.Canvas(status_frame, width=20, height=20)
        self.indicator_canvas.pack(side=tk.LEFT, padx=(5, 0))
        self.indicator = self.indicator_canvas.create_oval(5, 5, 15, 15, fill="gray")
        self.status_label = ttk.Label(status_frame, text="Статус: Выключен", font=("Arial", 10, "bold"))
        self.status_label.pack(side=tk.LEFT, padx=10)

        # --- Контроль ---
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.start_btn = ttk.Button(control_frame, text="Включить", width=15, command=self.start_proxy)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(control_frame, text="Выключить", width=15, command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.exit_btn = ttk.Button(control_frame, text="Закрыть", width=15, command=self.on_close)
        self.exit_btn.pack(side=tk.RIGHT, padx=5)

        # --- Лог ---
        log_frame = ttk.LabelFrame(main_frame, text="Журнал событий")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10, state='disabled', font=("Consolas", 9))
        self.log_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        
        export_frame = ttk.Frame(log_frame)
        export_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        self.export_log_btn = ttk.Button(export_frame, text="Выгрузить лог", command=self.save_log_to_file)
        self.export_log_btn.pack(side=tk.RIGHT)

    def start_stats_timer(self) -> None:
        def check_and_save_stats() -> None:
            if self._is_closing: return
            try:
                now = datetime.datetime.now()
                current_hour = now.replace(minute=0, second=0, microsecond=0)
                if self.last_saved_hour is None:
                    self.last_saved_hour = current_hour
                if current_hour > self.last_saved_hour:
                    self.save_traffic_stats()
                    self.last_saved_hour = current_hour
            except Exception as e:
                logger.error(f"Ошибка таймера: {e}")
            finally:
                self.root.after(60000, check_and_save_stats)
        self.root.after(60000, check_and_save_stats)

    def save_traffic_stats(self) -> None:
        try:
            upload_diff = self.upload_bytes - self.last_hour_stats['upload']
            download_diff = self.download_bytes - self.last_hour_stats['download']
            if upload_diff == 0 and download_diff == 0:
                return
            hour_start = self.last_saved_hour
            if not hour_start: return
            timestamp = hour_start.strftime("%Y-%m-%d %H:%M:%S")
            file_exists = os.path.exists(self.stats_file)
            with open(self.stats_file, 'a', newline='', encoding='utf-8') as stats_file:
                if not file_exists:
                    stats_file.write('Timestamp,Upload (bytes),Download (bytes)\n')
                stats_file.write(f'{timestamp},{upload_diff},{download_diff}\n')
            self.last_hour_stats = {'upload': self.upload_bytes, 'download': self.download_bytes}
        except Exception as e:
            logger.error(f"Ошибка статистики: {e}")

    def setup_entry_bindings(self, entry: ttk.Entry) -> None:
        entry.bind("<Control-c>", lambda e: self.copy_to_clipboard(entry))
        entry.bind("<Control-v>", lambda e: self.paste_from_clipboard(entry))
        entry.bind("<Control-a>", self.select_all)

    def select_all(self, event: tk.Event) -> str:
        event.widget.select_range(0, tk.END)
        event.widget.icursor(tk.END)
        return "break"

    def copy_to_clipboard(self, entry: ttk.Entry) -> None:
        try:
            if entry.selection_present():
                text = entry.selection_get()
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
        except tk.TclError: pass

    def paste_from_clipboard(self, entry: ttk.Entry) -> None:
        try:
            text = self.root.clipboard_get()
            if text:
                if entry.selection_present():
                    entry.delete(tk.SEL_FIRST, tk.SEL_LAST)
                entry.insert(tk.INSERT, text)
        except tk.TclError: pass

    def update_traffic_stats(self) -> None:
        def format_bytes(size: float) -> str:
            for unit in ['Б', 'КБ', 'МБ', 'ГБ']:
                if size < 1024.0: return f"{size:.2f} {unit}"
                size /= 1024.0
            return f"{size:.2f} ТБ"

        if self._is_closing: return
        try:
            now = datetime.datetime.now()
            current_hour = now.replace(minute=0, second=0, microsecond=0)
            if self.last_saved_hour is not None and current_hour > self.last_saved_hour:
                hour_upload = self.upload_bytes - self.last_hour_stats['upload']
                hour_download = self.download_bytes - self.last_hour_stats['download']
                self.hour_upload_label.config(text=f"Отправлено: {format_bytes(hour_upload)}")
                self.hour_download_label.config(text=f"Получено: {format_bytes(hour_download)}")
            
            self.session_upload_label.config(text=f"Отправлено: {format_bytes(self.session_upload_bytes)}")
            self.session_download_label.config(text=f"Получено: {format_bytes(self.session_download_bytes)}")
        except tk.TclError:
            pass

    def reset_traffic_stats(self) -> None:
        self.upload_bytes = 0
        self.download_bytes = 0
        self.session_upload_bytes = 0
        self.session_download_bytes = 0
        self.last_hour_stats = {'upload': 0, 'download': 0}
        self.update_traffic_stats()
        self.log_message("Статистика очищена.")

    def log_message(self, message: str) -> None:
        def append() -> None:
            if self._is_closing: return
            try:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                full_message = f"[{timestamp}] {message}\n"
                self.log_text.config(state='normal')
                self.log_text.insert(tk.END, full_message)
                self.log_text.config(state='disabled')
                self.log_text.see(tk.END)
                if len(self.log_text.get("1.0", tk.END)) > 10000:
                    self.log_text.config(state='normal')
                    self.log_text.delete("1.0", "2000.0")
                    self.log_text.config(state='disabled')
            except tk.TclError:
                pass
        self.root.after(0, append)

    def save_log_to_file(self) -> None:
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"proxy_log_{timestamp}.txt"
            content = self.log_text.get("1.0", tk.END)
            with open(filename, "w", encoding="utf-8") as f:
                f.write(content)
            self.log_message(f"Лог сохранён: {filename}")
        except Exception as e:
            logger.error(f"Ошибка сохранения лога: {e}")

    def add_custom_domains(self) -> None:
        text = self.custom_text.get("1.0", tk.END).strip()
        if not text: return
        domains = [line.strip() for line in text.splitlines() if line.strip()]
        new_count = 0
        for domain in domains:
            try:
                encoded = domain.encode('idna') if domain.isascii() else domain.encode('utf-8')
                if encoded not in self.BLOCKED:
                    self.BLOCKED.add(encoded)
                    new_count += 1
            except Exception as e:
                self.log_message(f"Ошибка домена '{domain}': {str(e)}")
        self.custom_text.delete("1.0", tk.END)
        self.log_message(f"Добавлено доменов: {new_count}")

    def load_domains_from_file(self) -> None:
        file_path = filedialog.askopenfilename(title="Выберите файл", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not file_path: return
            
        self.last_file_path.set(f"Последний файл: {os.path.basename(file_path)}")
        self.load_file_btn.config(state=tk.DISABLED)
        self.loading_status.set("Чтение файла...")
        
        async def async_load_file() -> None:
            try:
                domains = await self.parse_domains_from_file(file_path)
                if not domains:
                    self.log_message("Файл пуст.")
                    return
                self.BLOCKED = domains
                self.log_message(f"✅ Загружено {len(self.BLOCKED)} доменов")
                self.save_config(last_file_path=file_path)
                self.root.after(0, self.start_server)
            except Exception as e:
                self.log_message(f"Ошибка: {str(e)}")
            finally:
                self.root.after(0, lambda: self.load_file_btn.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.loading_status.set("Готов"))
        
        threading.Thread(target=lambda: asyncio.run(async_load_file()), daemon=True).start()

    async def parse_domains_from_file(self, file_path: str) -> Set[bytes]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            domains = set()
            lines = content.splitlines()
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'): continue
                try:
                    domains.add(stripped.encode('idna'))
                except: pass
            return domains
        except Exception as e:
            self.log_message(f"Ошибка чтения: {e}")
            return set()

    async def fetch_domains(self, url: str) -> Set[bytes]:
        self.loading_status.set("Подключение...")
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP Error {response.status}")
                    self.loading_status.set("Загрузка данных...")
                    text = await response.text()
                    
                    domains = set()
                    lines = text.splitlines()
                    for line in lines:
                        stripped = line.strip()
                        if not stripped or stripped.startswith('#'): continue
                        try:
                            domains.add(stripped.encode('idna'))
                        except:
                            try:
                                domains.add(stripped.encode('utf-8'))
                            except: pass
                    
                    self.loading_status.set("Готов")
                    return domains
        except Exception as e:
            self.loading_status.set("Ошибка загрузки")
            self.log_message(f"Ошибка URL: {e}")
            raise

    def load_blocked_domains_and_start(self) -> None:
        url = self.last_url.get().strip()
        if not url or not self.is_valid_url(url):
            self.log_message("Некорректный URL.")
            return
        
        self.load_btn.config(state=tk.DISABLED)
        self.loading_status.set("Инициализация...")
        
        async def async_load() -> None:
            try:
                domains = await self.fetch_domains(url)
                if not domains:
                    self.log_message("Список пуст.")
                    return
                self.BLOCKED = domains
                self.log_message(f"✅ Загружено {len(self.BLOCKED)} доменов")
                self.save_config(last_url=url)
                self.root.after(0, self.start_server)
            except Exception as e:
                self.log_message(f"Ошибка: {str(e)}")
            finally:
                self.root.after(0, lambda: self.load_btn.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.loading_status.set("Готов"))
        
        threading.Thread(target=lambda: asyncio.run(async_load()), daemon=True).start()

    def start_proxy(self) -> None:
        if self.BLOCKED:
            self.start_server()
        else:
            self.load_blocked_domains_and_start()

    def start_server(self) -> None:
        if self.running:
            self.log_message("Сервер уже запущен.")
            return
        if not self.BLOCKED:
            self.log_message("Список доменов пуст.")
            return
        
        self.running = True
        self.update_indicator(True)
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.session_upload_bytes = 0
        self.session_download_bytes = 0
        self.last_saved_hour = datetime.datetime.now().replace(minute=0, second=0, microsecond=0)
        threading.Thread(target=self.run_asyncio, daemon=True).start()

    def run_asyncio(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.server_task = self.loop.create_task(self.run_server())
            self.loop.run_until_complete(self.server_task)
        except Exception as e:
            self.log_message(f"Ошибка цикла: {e}")
        finally:
            if self.loop: self.loop.close()
            self.loop = None
            self.root.after(0, self._update_ui_after_stop)

    def _update_ui_after_stop(self) -> None:
        self.running = False
        self.update_indicator(False)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log_message("Сервер остановлен.")

    async def pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, is_upload: bool) -> None:
        try:
            while not reader.at_eof():
                if self.server_task and self.server_task.done(): break
                data = await reader.read(1500)
                if not data: break  # ИСПРАВЛЕНО
                writer.write(data)
                await writer.drain()
                size = len(data)
                if is_upload:
                    self.upload_bytes += size
                    self.session_upload_bytes += size
                else:
                    self.download_bytes += size
                    self.session_download_bytes += size
                
                current_time = asyncio.get_event_loop().time()
                if current_time - self.last_update_time > 0.5:
                    self.last_update_time = current_time
                    self.root.after(0, self.update_traffic_stats)
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError): pass
        except Exception as e: self.log_message(f"[PIPE] Ошибка: {e}")
        finally:
            if not writer.is_closing():
                writer.close()
                try: await writer.wait_closed()
                except: pass

    async def fragment_data(self, local_reader: asyncio.StreamReader, remote_writer: asyncio.StreamWriter) -> None:
        try:
            head = await local_reader.read(5)
            if len(head) < 5: return
            data = await local_reader.read(1500)
            if not data: return  # ИСПРАВЛЕНО
            
            blocked_found = False
            for site in self.BLOCKED:
                if site in data:  # ИСПРАВЛЕНО
                    blocked_found = True
                    break
            
            if not blocked_found:
                remote_writer.write(head + data)
                await remote_writer.drain()
                return

            self.log_message("Фрагментирование соединения.")
            parts = []
            while data:  # ИСПРАВЛЕНО
                part_len = random.randint(1, len(data))
                fragment_header = (
                    bytes.fromhex("1603") + 
                    bytes([random.randint(0, 255)]) + 
                    part_len.to_bytes(2, byteorder='big')
                )
                parts.append(fragment_header + data[:part_len])
                data = data[part_len:]
            remote_writer.write(b''.join(parts))
            await remote_writer.drain()
        except Exception as e:
            self.log_message(f"[FRAGMENT] Ошибка: {e}")

    async def handle_connection(self, local_reader: asyncio.StreamReader, local_writer: asyncio.StreamWriter) -> None:
        addr = local_writer.get_extra_info('peername')
        if addr is None: return
        try:
            http_data = await asyncio.wait_for(local_reader.read(1500), timeout=10.0)
            if not http_data: return  # ИСПРАВЛЕНО
            first_line = http_data.split(b"\r\n")[0]
            parts = first_line.split(b" ")
            if len(parts) < 3 or parts[0] != b"CONNECT": return
            
            host_port = parts[1].split(b":")
            if len(host_port) != 2: return
            host, port = host_port[0], int(host_port[1])
            
            try:
                host_str = host.decode('idna') if host.isascii() else host.decode('utf-8', 'ignore')
            except: host_str = host.decode('latin-1', 'ignore')
            
            local_writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await local_writer.drain()
            
            try:
                remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection(host_str, port), timeout=10.0)
                self.active_connections.append((remote_reader, remote_writer))
            except Exception as e:
                return
            
            try:
                if port == 443:
                    await self.fragment_data(local_reader, remote_writer)
                task1 = asyncio.create_task(self.pipe(local_reader, remote_writer, is_upload=True))
                task2 = asyncio.create_task(self.pipe(remote_reader, local_writer, is_upload=False))
                self.tasks.extend([task1, task2])
                await asyncio.gather(task1, task2, return_exceptions=True)
            finally:
                if (remote_reader, remote_writer) in self.active_connections:
                    self.active_connections.remove((remote_reader, remote_writer))
                try:
                    remote_writer.close()
                    await remote_writer.wait_closed()
                except: pass
        except asyncio.TimeoutError: pass
        except Exception as e: self.log_message(f"[HANDLER] Ошибка: {e}")
        finally:
            try:
                local_writer.close()
                await local_writer.wait_closed()
            except: pass

    async def run_server(self) -> None:
        server = None
        try:
            server = await asyncio.start_server(self.handle_connection, '127.0.0.1', 8881, reuse_address=True)
            self.server = server
            self.log_message(f"Сервер запущен на localhost:8881")
            async with server:
                await server.serve_forever()
        except asyncio.CancelledError: self.log_message("Сервер отключен.")
        except OSError as e:
            self.log_message(f"Ошибка порта: {e}. Порт занят?")
        except Exception as e: self.log_message(f"[SERVER] Ошибка: {e}")
        finally:
            if server: server.close()
            self.server = None

    def stop_server(self) -> None:
        if not self.running: return
        self.running = False
        self.update_indicator(False)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        if self.server_task and not self.server_task.done(): self.server_task.cancel()
        for _, writer in self.active_connections[:]:
            try: writer.close()
            except: pass
        self.active_connections.clear()
        if self.tasks and self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(self.wait_for_tasks_completion(), self.loop)
        else: self.tasks.clear()
        self.log_message("Сервер останавливается...")

    async def wait_for_tasks_completion(self) -> None:
        if not self.tasks: return
        done, pending = await asyncio.wait(self.tasks, timeout=5.0, return_when=asyncio.ALL_COMPLETED)
        for task in pending:
            task.cancel()
            try: await task
            except asyncio.CancelledError: pass
        self.tasks.clear()

    def update_indicator(self, status: bool) -> None:
        color = "green" if status else "gray"
        self.indicator_canvas.itemconfig(self.indicator, fill=color)
        self.status_label.config(text="Статус: " + ("Включён" if status else "Выключен"))
        if self.tray_icon:
            try:
                image = Image.new('RGB', (64, 64), color=(50, 50, 50))
                draw = ImageDraw.Draw(image)
                draw.ellipse((16, 16, 48, 48), fill="green" if status else "gray")
                self.tray_icon.icon = image
            except: pass

    def create_tray_icon(self) -> None:
        if self.tray_icon is not None: return
        
        try:
            image = Image.new('RGB', (64, 64), color=(50, 50, 50))
            draw = ImageDraw.Draw(image)
            draw.ellipse((16, 16, 48, 48), fill="green" if self.running else "gray")
            
            menu = (
                pystray.MenuItem('Открыть', lambda: self.restore_window()),
                pystray.MenuItem('Включить', lambda: self.start_server(), enabled=not self.running),
                pystray.MenuItem('Выключить', lambda: self.stop_server(), enabled=self.running),
                pystray.MenuItem('Выход', lambda: self.quit_application())
            )
            
            # ДОБАВЛЕНО: on_click=self.restore_window для открытия по ЛКМ
            self.tray_icon = pystray.Icon(
                "proxy_icon", 
                image, 
                "HTTPS Прокси", 
                menu,
                on_click=self.restore_window  # <-- Эта строка активирует открытие по клику
            )
            
            def run_tray():
                try:
                    self._tray_ready.set()
                    self.tray_icon.run()
                except Exception as e:
                    logger.error(f"Ошибка трея: {e}")
                    self._tray_ready.clear()
            
            tray_thread = threading.Thread(target=run_tray, daemon=True)
            tray_thread.start()
            
            self._tray_ready.wait(timeout=2.0)
            
        except Exception as e:
            logger.error(f"Не удалось создать иконку в трее: {e}")
        self.log_message("Внимание: иконка в трее не создана")

    def minimize_window(self) -> None:
        if self.minimize_to_tray.get():
            self.root.withdraw()
            self.log_message("Окно скрыто. Используйте иконку в трее для возврата.")
        else:
            self.on_close()

    def restore_window(self) -> None:
        def do_restore():
            try:
                self.root.deiconify()
                self.root.lift()
                self.root.focus_force()
                self.log_message("Окно восстановлено")
            except Exception as e:
                logger.error(f"Ошибка восстановления: {e}")
        
        self.root.after(0, do_restore)

    def quit_application(self) -> None:
        if self._is_closing: return
        self._is_closing = True
        try:
            if self.tray_icon is not None:
                try:
                    self.tray_icon.stop()
                except: pass
                self.tray_icon = None
            self._tray_ready.clear()
            
            self.stop_server()
            self.save_traffic_stats()
            self.save_config()
            
            self.root.after(0, self.root.destroy)
        except Exception as e:
            logger.error(f"Ошибка при завершении: {e}")
            os._exit(0)

    def on_close(self) -> None:
        if self.running:
            if messagebox.askokcancel("Выход", "Прокси-сервер работает. Выйти?"):
                self.quit_application()
        else:
            self.quit_application()

    @staticmethod
    def main() -> None:
        root = tk.Tk()
        try:
            root.tk.call('tk', 'scaling', 1.5)
        except:
            pass
        app = ProxyApp(root)
        root.mainloop()

if __name__ == "__main__":
    ProxyApp.main()