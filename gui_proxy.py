import random
import asyncio
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import datetime
import aiohttp
import threading
import pystray
from PIL import Image, ImageDraw
import os
import re
import logging
from typing import Set, Tuple, Optional, Dict, Any

# Настройка логгера для внутреннего использования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ProxyApp")

class SimpleIni:
    """Улучшенная реализация INI-файла с проверкой типов и безопасной записью."""
    def __init__(self):
        self.sections: Dict[str, Dict[str, str]] = {}
    
    def read(self, filename: str) -> None:
        """Безопасное чтение INI-файла с обработкой ошибок."""
        try:
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
        """Безопасная запись INI-файла с временным файлом для целостности данных."""
        try:
            temp_filename = filename + '.tmp'
            with open(temp_filename, 'w', encoding='utf-8') as f:
                for section, options in self.sections.items():
                    f.write(f'[{section}]\n')
                    for option, value in options.items():
                        f.write(f'{option}={value}\n')
                    f.write('\n')
            # Заменяем оригинальный файл только после успешной записи
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
    
    def getint(self, section: str, option: str, fallback: Optional[int] = None) -> int:
        val = self.get(section, option)
        if val is None:
            return fallback if fallback is not None else 0
        try:
            return int(val)
        except (TypeError, ValueError):
            return fallback if fallback is not None else 0
    
    def get(self, section: str, option: str, fallback: Optional[str] = None) -> Optional[str]:
        return self.sections.get(section, {}).get(option, fallback)
    
    def set(self, section: str, option: str, value: Any) -> None:
        if section not in self.sections:
            self.sections[section] = {}
        self.sections[section][option] = str(value)

class ProxyApp:
    """Основной класс приложения с HTTPS прокси и графическим интерфейсом."""
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("HTTPS Прокси")
        self.root.geometry("800x650")
        self.root.minsize(800, 800)
        self.root.resizable(True, True)
        # Инициализация переменных
        self.server_task: Optional[asyncio.Task] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.running = False
        self.tasks: list = []
        self.active_connections: list = []
        self.log_size = 0
        self.max_log_size = 1024 * 1024  # 1 MB
        self.BLOCKED: Set[bytes] = set()
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
        # Инициализация конфигурации
        self.config = SimpleIni()
        # UI-переменные
        self.auto_start = tk.BooleanVar(value=False)
        self.minimize_to_tray = tk.BooleanVar(value=True)
        self.last_url = tk.StringVar(value=self.default_url)
        self.loading_progress = tk.DoubleVar(value=0)
        self.loading_status = tk.StringVar(value="Готов")
        # Загрузка конфигурации
        self.load_config()
        # Создание интерфейса
        self.create_gui()
        # Автозапуск, если настроено
        if self.auto_start.get():
            self.root.after(100, self.load_blocked_domains_and_start)
        # Таймер для периодического сохранения статистики
        self.start_stats_timer()
        # Регистрация обработчика завершения работы
        self.root.protocol("WM_DELETE_WINDOW", self.minimize_window)
        self.log_message("Приложение запущено и готово к работе.")
    
    def save_config(self, **kwargs) -> None:
        """Сохраняет текущую конфигурацию с обработкой ошибок."""
        try:
            if not self.config.has_section('Settings'):
                self.config.sections['Settings'] = {}
            # Сохраняем параметры из вызова
            for key, value in kwargs.items():
                self.config.set('Settings', key, str(value))
            # Сохраняем актуальные значения из интерфейса
            self.config.set('Settings', 'auto_start', str(self.auto_start.get()))
            self.config.set('Settings', 'minimize_to_tray', str(self.minimize_to_tray.get()))
            self.config.set('Settings', 'last_url', self.last_url.get())
            # Дополнительные параметры
            self.config.write(self.config_file)
        except Exception as e:
            self.log_message(f"Ошибка сохранения настроек: {e}")
    
    def load_config(self) -> None:
        """Загружает конфигурацию из файла с проверкой значений."""
        # Чтение конфигурации
        self.config.read(self.config_file)
        # Установка значений с проверкой
        try:
            self.auto_start.set(self.config.getboolean('Settings', 'auto_start', False))
            self.minimize_to_tray.set(self.config.getboolean('Settings', 'minimize_to_tray', True))
            url = self.config.get('Settings', 'last_url', self.default_url)
            if self.is_valid_url(url):
                self.last_url.set(url)
            else:
                self.last_url.set(self.default_url)
                self.log_message("Некорректный URL в конфигурации, использован URL по умолчанию")
        except Exception as e:
            self.log_message(f"Ошибка парсинга конфига: {e}, использованы значения по умолчанию")
            self.auto_start.set(False)
            self.minimize_to_tray.set(True)
            self.last_url.set(self.default_url)
        # Сохраняем конфигурацию с актуальными значениями
        self.save_config()
    
    def is_valid_url(self, url: str) -> bool:
        """Проверяет корректность URL с использованием регулярного выражения."""
        url_pattern = re.compile(
            r'^(https?://)'  # http:// или https://
            r'([a-zA-Z0-9.-]+)'  # доменное имя или IP
            r'(:\d+)?'  # необязательный порт
            r'(/[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=%-]*)*$',  # путь
            re.IGNORECASE
        )
        return bool(url_pattern.match(url))
    
    def create_gui(self) -> None:
        """Создает графический интерфейс с улучшенной структурой и элементами."""
        # Создаем основные фреймы
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        # Фрейм для URL и загрузки
        url_frame = ttk.LabelFrame(main_frame, text="Настройки блокировки доменов")
        url_frame.pack(fill=tk.X, pady=(0, 10))
        # URL ввод
        ttk.Label(url_frame, text="URL списка доменов:").pack(anchor=tk.W, padx=5, pady=(5, 0))
        url_entry_frame = ttk.Frame(url_frame)
        url_entry_frame.pack(fill=tk.X, padx=5, pady=5)
        self.url_entry = ttk.Entry(url_entry_frame, textvariable=self.last_url)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.setup_entry_bindings(self.url_entry)
        self.load_btn = ttk.Button(url_entry_frame, text="Загрузить", command=self.load_blocked_domains_and_start)
        self.load_btn.pack(side=tk.RIGHT, padx=(5, 0))
        # Фрейм для ручного добавления доменов
        custom_frame = ttk.LabelFrame(main_frame, text="Ручное добавление доменов")
        custom_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(custom_frame, text="Добавить свои домены (по одному или списком):").pack(anchor=tk.W, padx=5, pady=(5, 0))
        custom_text_frame = ttk.Frame(custom_frame)
        custom_text_frame.pack(fill=tk.X, padx=5, pady=5)
        self.custom_text = tk.Text(custom_text_frame, height=3)
        self.custom_text.pack(fill=tk.X, side=tk.LEFT, expand=True)
        scrollbar = ttk.Scrollbar(custom_text_frame, command=self.custom_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.custom_text['yscrollcommand'] = scrollbar.set
        self.add_btn = ttk.Button(custom_frame, text="Добавить", command=self.add_custom_domains)
        self.add_btn.pack(anchor=tk.E, padx=5, pady=5)
        # Настройки приложения
        settings_frame = ttk.LabelFrame(main_frame, text="Настройки приложения")
        settings_frame.pack(fill=tk.X, pady=(0, 10))
        settings_content = ttk.Frame(settings_frame)
        settings_content.pack(fill=tk.X, padx=5, pady=5)
        ttk.Checkbutton(
            settings_content, 
            text="Автостарт прокси", 
            variable=self.auto_start,
            command=lambda: self.save_config(auto_start=self.auto_start.get())
        ).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Checkbutton(
            settings_content, 
            text="Сворачивать в трей", 
            variable=self.minimize_to_tray,
            command=lambda: self.save_config(minimize_to_tray=self.minimize_to_tray.get())
        ).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        # Статистика трафика
        traffic_frame = ttk.LabelFrame(main_frame, text="Статистика трафика")
        traffic_frame.pack(fill=tk.X, pady=(0, 10))
        # Статистика за последний час
        hour_frame = ttk.Frame(traffic_frame)
        hour_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(hour_frame, text="За последний час:").pack(side=tk.LEFT)
        self.hour_upload_label = ttk.Label(hour_frame, text="Отправлено: 0 Б")
        self.hour_upload_label.pack(side=tk.LEFT, padx=10)
        self.hour_download_label = ttk.Label(hour_frame, text="Получено: 0 Б")
        self.hour_download_label.pack(side=tk.LEFT)
        # Статистика за текущую сессию
        session_frame = ttk.Frame(traffic_frame)
        session_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(session_frame, text="За сессию:").pack(side=tk.LEFT)
        self.session_upload_label = ttk.Label(session_frame, text="Отправлено: 0 Б")
        self.session_upload_label.pack(side=tk.LEFT, padx=10)
        self.session_download_label = ttk.Label(session_frame, text="Получено: 0 Б")
        self.session_download_label.pack(side=tk.LEFT)
        # Кнопка сброса статистики
        self.reset_traffic_btn = ttk.Button(
            traffic_frame, 
            text="Сбросить", 
            command=self.reset_traffic_stats
        )
        self.reset_traffic_btn.pack(anchor=tk.E, padx=5, pady=5)
        # Индикатор статуса сервера
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        self.indicator_canvas = tk.Canvas(status_frame, width=20, height=20)
        self.indicator_canvas.pack(side=tk.LEFT, padx=(5, 0))
        self.indicator = self.indicator_canvas.create_oval(5, 5, 15, 15, fill="gray")
        self.status_label = ttk.Label(status_frame, text="Статус: Выключен", font=("Arial", 10))
        self.status_label.pack(side=tk.LEFT, padx=10)
        # Контроль запуска и остановки сервера
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        self.start_btn = ttk.Button(
            control_frame, 
            text="Включить", 
            width=10, 
            command=self.start_proxy
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(
            control_frame, 
            text="Выключить", 
            width=10, 
            command=self.stop_server,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.exit_btn = ttk.Button(
            control_frame, 
            text="Закрыть", 
            width=10, 
            command=self.on_close
        )
        self.exit_btn.pack(side=tk.RIGHT, padx=5)
        # Поле логирования
        log_frame = ttk.LabelFrame(main_frame, text="Журнал событий")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.log_text = scrolledtext.ScrolledText(
            log_frame, 
            wrap=tk.WORD, 
            height=12,
            state='disabled',
            font=("Consolas", 9)
        )
        self.log_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
    
    def start_stats_timer(self) -> None:
        """Инициализирует таймер для регулярного сохранения статистики трафика."""
        def check_and_save_stats() -> None:
            try:
                now = datetime.datetime.now()
                current_hour = now.replace(minute=0, second=0, microsecond=0)
                # Инициализируем last_saved_hour при первом запуске
                if self.last_saved_hour is None:
                    self.last_saved_hour = current_hour
                # Проверяем, прошел ли целый час с момента последнего сохранения
                if current_hour > self.last_saved_hour:
                    self.save_traffic_stats()
                    self.last_saved_hour = current_hour
            except Exception as e:
                self.log_message(f"Ошибка в таймере статистики: {e}")
            finally:
                self.root.after(60000, check_and_save_stats)  # Проверять каждые 60 секунд
        
        self.root.after(60000, check_and_save_stats)  # Первый запуск через минуту
    
    def save_traffic_stats(self) -> None:
        """Сохраняет статистику трафика за последний час в CSV-файл."""
        try:
            # Разница между текущими значениями и предыдущей записью
            upload_diff = self.upload_bytes - self.last_hour_stats['upload']
            download_diff = self.download_bytes - self.last_hour_stats['download']
            # Пустой трафик пропускаем
            if upload_diff == 0 and download_diff == 0:
                return
            # Подготавливаем строку времени для сохранения
            hour_start = self.last_saved_hour
            timestamp = hour_start.strftime("%Y-%m-%d %H:%M:%S")
            # Проверяем существование файла
            file_exists = os.path.exists(self.stats_file)
            # Записываем данные
            with open(self.stats_file, 'a', newline='', encoding='utf-8') as stats_file:
                if not file_exists:
                    stats_file.write('Timestamp,Upload (bytes),Download (bytes)\n')
                stats_file.write(f'{timestamp},{upload_diff},{download_diff}\n')
            # Обновляем предыдущий статус
            self.last_hour_stats = {
                'upload': self.upload_bytes,
                'download': self.download_bytes
            }
            self.log_message(f"Сохранена статистика за час: Отправлено {upload_diff} Б, Получено {download_diff} Б")
        except Exception as e:
            self.log_message(f"Ошибка сохранения статистики: {e}")
    
    def setup_entry_bindings(self, entry: ttk.Entry) -> None:
        """Настраивает горячие клавиши для копирования-вставки текста."""
        entry.bind("<Control-c>", lambda e: self.copy_to_clipboard(entry))
        entry.bind("<Control-v>", lambda e: self.paste_from_clipboard(entry))
        entry.bind("<Control-x>", lambda e: self.cut_to_clipboard(entry))
        entry.bind("<Control-a>", self.select_all)
    
    def select_all(self, event: tk.Event) -> str:
        """Выделяет весь текст в поле ввода."""
        event.widget.select_range(0, tk.END)
        event.widget.icursor(tk.END)
        return "break"
    
    def copy_to_clipboard(self, entry: ttk.Entry) -> None:
        """Копирует выделенный текст в буфер обмена."""
        try:
            if entry.selection_present():
                text = entry.selection_get()
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
        except tk.TclError:
            pass
    
    def paste_from_clipboard(self, entry: ttk.Entry) -> None:
        """Вставляет текст из буфера обмена в элемент ввода."""
        try:
            text = self.root.clipboard_get()
            if text:
                if entry.selection_present():
                    entry.delete(tk.SEL_FIRST, tk.SEL_LAST)
                entry.insert(tk.INSERT, text)
        except tk.TclError:
            pass
    
    def cut_to_clipboard(self, entry: ttk.Entry) -> None:
        """Вырезает выделенный текст и помещает его в буфер обмена."""
        self.copy_to_clipboard(entry)
        if entry.selection_present():
            entry.delete(tk.SEL_FIRST, tk.SEL_LAST)
    
    def update_traffic_stats(self) -> None:
        """Обновляет визуализацию статистики трафика."""
        def format_bytes(size: float) -> str:
            """Форматирует байты в человекочитаемый вид."""
            for unit in ['Б', 'КБ', 'МБ', 'ГБ']:
                if size < 1024.0:
                    return f"{size:.2f} {unit}"
                size /= 1024.0
            return f"{size:.2f} ТБ"
        
        # Расчет статистики за последний час
        now = datetime.datetime.now()
        current_hour = now.replace(minute=0, second=0, microsecond=0)
        if self.last_saved_hour is not None and current_hour > self.last_saved_hour:
            hour_upload = self.upload_bytes - self.last_hour_stats['upload']
            hour_download = self.download_bytes - self.last_hour_stats['download']
            self.hour_upload_label.config(text=f"Отправлено: {format_bytes(hour_upload)}")
            self.hour_download_label.config(text=f"Получено: {format_bytes(hour_download)}")
        
        # Обновляем общий счётчик за сессию
        self.session_upload_label.config(text=f"Отправлено: {format_bytes(self.session_upload_bytes)}")
        self.session_download_label.config(text=f"Получено: {format_bytes(self.session_download_bytes)}")
    
    def reset_traffic_stats(self) -> None:
        """Очищает статистику трафика и сбрасывает её отображение."""
        self.upload_bytes = 0
        self.download_bytes = 0
        self.session_upload_bytes = 0
        self.session_download_bytes = 0
        self.last_hour_stats = {'upload': 0, 'download': 0}
        self.update_traffic_stats()
        self.log_message("Статистика трафика была успешно очищена.")
    
    def log_message(self, message: str) -> None:
        """Выводит сообщение в окно лога с ограничением размера."""
        def append() -> None:
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
            if len(self.log_text.get("1.0", tk.END)) > 5000:  # ~5000 строк
                self.log_text.config(state='normal')
                self.log_text.delete("1.0", "1000.0")  # Удаляем первые 1000 строк
                self.log_text.config(state='disabled')
        
        self.root.after(0, append)
    
    def save_log_to_file(self) -> None:
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
    
    def add_custom_domains(self) -> None:
        """Добавляет указанные пользователем домены в блокировку."""
        text = self.custom_text.get("1.0", tk.END).strip()
        if not text:
            return
        domains = [line.strip() for line in text.splitlines() if line.strip()]
        new_count = 0
        for domain in domains:
            try:
                # Пытаемся закодировать домен в IDNA, если это возможно
                encoded = domain.encode('idna') if domain.isascii() else domain.encode('utf-8')
                if encoded not in self.BLOCKED:
                    self.BLOCKED.add(encoded)
                    new_count += 1
            except Exception as e:
                self.log_message(f"Ошибка обработки домена '{domain}': {str(e)}")
                continue
        self.custom_text.delete("1.0", tk.END)
        self.log_message(f"Добавлено вручную доменов: {new_count}")
    
    async def fetch_domains(self, url: str) -> Set[bytes]:
        """Асинхронно получает список заблокированных доменов по указанному URL."""
        self.root.after(0, lambda: self._update_loading_status("Загрузка...", 0))
        async with aiohttp.ClientSession() as session:
            try:
                self.root.after(0, lambda: self._update_loading_status("Подключение...", 10))
                async with session.get(url, timeout=30) as resp:
                    if resp.status != 200:
                        raise Exception(f"HTTP {resp.status} {resp.reason}")
                    total_size = int(resp.headers.get('Content-Length', 0))
                    downloaded = 0
                    chunks = []
                    self.root.after(0, lambda: self._update_loading_status("Получение данных...", 20))
                    async for chunk in resp.content.iter_chunked(1024):
                        chunks.append(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            progress = min(90, 20 + int(70 * downloaded / total_size))
                            self.root.after(0, lambda p=progress: self._update_loading_status("Получение данных...", p))
                    text = b''.join(chunks).decode('utf-8', 'ignore')
                    domains = set()
                    # Основное исправление: используем строковый литерал '#' вместо байтового b'#'
                    for line in text.splitlines():
                        stripped = line.strip()
                        if not stripped or stripped.startswith('#'):
                            continue
                        try:
                            # Пытаемся закодировать домен в IDNA
                            domain_bytes = stripped.encode('idna')
                            domains.add(domain_bytes)
                        except Exception as e:
                            try:
                                # Если IDNA не работает, используем UTF-8
                                domain_bytes = stripped.encode('utf-8')
                                domains.add(domain_bytes)
                            except Exception as e:
                                # Если ничего не работает, пропускаем домен
                                continue
                    self.root.after(0, lambda: self._update_loading_status(f"Загружено {len(domains)} доменов", 100))
                    return domains
            except Exception as e:
                self.root.after(0, lambda: self._update_loading_status(f"Ошибка: {str(e)}", 0))
                self.log_message(f"Ошибка загрузки с URL: {e}")
                return set()
    
    def _update_loading_status(self, status: str, progress: float) -> None:
        """Обновляет статус и прогресс загрузки доменов."""
        self.loading_status.set(status)
        self.loading_progress.set(progress)
    
    def load_blocked_domains_and_start(self) -> None:
        """Загружает заблокированные домены и запускает сервер."""
        url = self.last_url.get().strip()
        if not url:
            self.log_message("URL не указан.")
            return
        if not self.is_valid_url(url):
            self.log_message("Некорректный URL. Пожалуйста, укажите правильный URL.")
            return
        self.load_btn.config(state=tk.DISABLED)
        self._update_loading_status("Инициализация...", 0)
        async def async_load() -> None:
            try:
                self.log_message("Загрузка доменов с URL...")
                domains = await self.fetch_domains(url)
                if not domains:
                    self.log_message("Список доменов пуст после загрузки.")
                    return
                self.BLOCKED = domains
                self.log_message(f"✅ Загружено {len(self.BLOCKED)} доменов")
                self.save_config(last_url=url)
                # Запускаем сервер после успешной загрузки
                self.root.after(0, self.start_server)
            except Exception as e:
                self.log_message(f"Ошибка загрузки: {str(e)}")
            finally:
                self.root.after(0, lambda: self.load_btn.config(state=tk.NORMAL))
        
        threading.Thread(target=lambda: asyncio.run(async_load()), daemon=True).start()
    
    def start_proxy(self) -> None:
        """Запускает процесс загрузки доменов и последующего старта прокси."""
        # Сначала загружаем домены
        self.load_blocked_domains_and_start()
    
    def get_asyncio_loop(self) -> asyncio.AbstractEventLoop:
        """Возвращает текущий цикл событий или создаёт новый."""
        try:
            loop = asyncio.get_running_loop()
            if loop.is_closed():
                raise RuntimeError("Цикл событий закрыт")
            return loop
        except (RuntimeError, AttributeError):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop
    
    async def pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, is_upload: bool) -> None:
        """Передаёт данные между двумя соединениями и подсчитывает объём передаваемых данных."""
        try:
            while not reader.at_eof():
                # Проверяем, не отменена ли задача сервера
                if self.server_task and self.server_task.done():
                    break
                data = await reader.read(1500)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
                # Подсчет объема трафика
                size = len(data)
                if is_upload:
                    self.upload_bytes += size
                    self.session_upload_bytes += size
                else:
                    self.download_bytes += size
                    self.session_download_bytes += size
                # Обновляем GUI не чаще раза в полсекунды
                current_time = asyncio.get_event_loop().time()
                if current_time - self.last_update_time > 0.5:
                    self.last_update_time = current_time
                    self.root.after(0, self.update_traffic_stats)
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError):
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
    
    async def fragment_data(self, local_reader: asyncio.StreamReader, remote_writer: asyncio.StreamWriter) -> None:
        """Осуществляет фрагментирование HTTP-запросов согласно логике nodpi.py."""
        try:
            # Сначала читаем заголовок SSL/TLS
            head = await local_reader.read(5)
            if len(head) < 5:
                return
            # Читаем данные фиксированного размера (как в nodpi.py)
            data = await local_reader.read(1500)
            if not data:
                return
            # Проверяем, содержится ли заблокированный домен в данных
            if all(site not in data for site in self.BLOCKED):
                # Если заблокированных доменов нет, отправляем данные как есть
                remote_writer.write(head + data)
                await remote_writer.drain()
                return
            # Если заблокированные домены найдены, фрагментируем данные
            self.log_message("Фрагментировано соединение.")
            parts = []
            while data:
                # Случайный размер фрагмента от 1 до длины оставшихся данных
                part_len = random.randint(1, len(data))
                # Создаем новый SSL-заголовок с рандомизацией:
                # - bytes.fromhex("1603") - тип записи и основная версия SSL/TLS
                # - случайный байт для подверсии (ключевое отличие от текущей реализации!)
                # - длина фрагмента
                fragment_header = (
                    bytes.fromhex("1603") + 
                    bytes([random.randint(0, 255)]) + 
                    part_len.to_bytes(2, byteorder='big')
                )
                # Добавляем фрагмент в список
                parts.append(fragment_header + data[:part_len])
                data = data[part_len:]
            # Отправляем все фрагменты
            remote_writer.write(b''.join(parts))
            await remote_writer.drain()
        except Exception as e:
            self.log_message(f"[FRAGMENT] Ошибка: {e}")
    
    async def handle_connection(self, local_reader: asyncio.StreamReader, local_writer: asyncio.StreamWriter) -> None:
        """Обрабатывает входящие соединения без ограничения на количество подключений."""
        addr = local_writer.get_extra_info('peername')
        if addr is None:
            return
        conn_id = f"{addr[0]}:{addr[1]}"
        self.log_message(f"Новое подключение: {conn_id}")
        try:
            # Таймаут на получение данных
            http_data = await asyncio.wait_for(local_reader.read(1500), timeout=10.0)
            if not http_data:
                return
            # Проверяем, является ли запрос CONNECT
            first_line = http_data.split(b"\r\n")[0]
            parts = first_line.split(b" ")
            if len(parts) < 3 or parts[0] != b"CONNECT":
                return
            # Извлекаем хост и порт
            try:
                host_port = parts[1].split(b":")
                if len(host_port) != 2:
                    return
                host, port = host_port
                port = int(port)
            except (ValueError, IndexError) as e:
                self.log_message(f"Некорректный CONNECT запрос: {parts[1]} — {e}")
                return
            try:
                host_str = host.decode('idna') if host.isascii() else host.decode('utf-8', 'ignore')
            except UnicodeDecodeError:
                host_str = host.decode('latin-1', 'ignore')
            self.log_message(f"Проксируем: {host_str}:{port}")
            # Отправляем подтверждение
            local_writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await local_writer.drain()
            try:
                # Подключаемся к целевому серверу
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host_str, port), 
                    timeout=10.0
                )
                self.active_connections.append((remote_reader, remote_writer))
            except Exception as e:
                self.log_message(f"Ошибка подключения к {host_str}:{port}: {e}")
                return
            try:
                # Обработка HTTPS-трафика (порт 443)
                if port == 443:
                    await self.fragment_data(local_reader, remote_writer)
                # Создаем задачи для двусторонней передачи данных
                task1 = asyncio.create_task(self.pipe(local_reader, remote_writer, is_upload=True))
                task2 = asyncio.create_task(self.pipe(remote_reader, local_writer, is_upload=False))
                self.tasks.extend([task1, task2])
                await asyncio.gather(task1, task2, return_exceptions=True)
            except Exception as e:
                self.log_message(f"[CONNECTION] Ошибка передачи: {e}")
            finally:
                # Удаляем соединение из списка активных
                if (remote_reader, remote_writer) in self.active_connections:
                    self.active_connections.remove((remote_reader, remote_writer))
                # Закрываем удаленные соединения
                try:
                    remote_writer.close()
                    await remote_writer.wait_closed()
                except:
                    pass
        except asyncio.TimeoutError:
            self.log_message(f"Тайм-аут подключения от {conn_id}")
        except Exception as e:
            self.log_message(f"[HANDLER] Ошибка: {e}")
        finally:
            # Закрываем локальное соединение
            try:
                local_writer.close()
                await local_writer.wait_closed()
            except:
                pass
    
    async def run_server(self) -> None:
        """Запускает прокси-сервер с обработкой ошибок."""
        server = None
        try:
            server = await asyncio.start_server(
                self.handle_connection,
                '127.0.0.1',
                8881,
                reuse_address=True
            )
            self.server = server
            self.log_message(f"Сервер запущен на localhost:8881")
            async with server:
                await server.serve_forever()
        except asyncio.CancelledError:
            self.log_message("Сервер отключен по запросу.")
        except OSError as e:
            self.log_message(f"[SERVER] Ошибка привязки порта: {e}")
            if "address already in use" in str(e).lower():
                self.log_message("Попробуйте изменить порт или закрыть другое приложение, использующее порт 8881.")
        except Exception as e:
            self.log_message(f"[SERVER] Неожиданная ошибка: {e}")
        finally:
            if server:
                server.close()
                try:
                    await server.wait_closed()
                except:
                    pass
            self.server = None
    
    def start_server(self) -> None:
        """Запускает сервер с проверкой состояния."""
        if self.running:
            self.log_message("Сервер уже запущен.")
            return
        if not self.BLOCKED:
            self.log_message("Список блокируемых доменов пуст. Сначала загрузите домены.")
            return
        self.running = True
        self.update_indicator(True)
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        # Сбрасываем показатели статистики сессии
        self.session_upload_bytes = 0
        self.session_download_bytes = 0
        self.update_traffic_stats()
        # Начинаем отсчёт часа заново
        self.last_saved_hour = datetime.datetime.now().replace(minute=0, second=0, microsecond=0)
        # Запускаем сервер в отдельном потоке
        threading.Thread(target=self.run_asyncio, daemon=True).start()
    
    def run_asyncio(self) -> None:
        """Запускает асинхронный цикл событий для сервера."""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.server_task = self.loop.create_task(self.run_server())
            self.loop.run_until_complete(self.server_task)
        except Exception as e:
            self.log_message(f"Ошибка основного цикла: {e}")
        finally:
            if self.loop:
                self.loop.close()
            self.loop = None
            self.root.after(0, self._update_ui_after_stop)
    
    def _update_ui_after_stop(self) -> None:
        """Обновляет интерфейс после остановки сервера."""
        self.running = False
        self.update_indicator(False)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.server_task = None
        self.log_message("Сервер остановлен.")
    
    async def wait_for_tasks_completion(self) -> None:
        """Ожидает завершения всех активных задач с таймаутом."""
        if not self.tasks:
            return
        done, pending = await asyncio.wait(
            self.tasks, 
            timeout=5.0,
            return_when=asyncio.ALL_COMPLETED
        )
        # Отменяем оставшиеся задачи
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self.tasks.clear()
    
    def stop_server(self) -> None:
        """Останавливает сервер и все активные соединения."""
        if not self.running:
            return
        self.running = False
        self.update_indicator(False)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        # Отменяем основную задачу сервера
        if self.server_task and not self.server_task.done():
            self.server_task.cancel()
        # Закрываем активные соединения
        for _, writer in self.active_connections[:]:
            try:
                writer.close()
            except:
                pass
        self.active_connections.clear()
        # Ожидаем завершения задач
        if self.tasks and self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(self.wait_for_tasks_completion(), self.loop)
        else:
            self.tasks.clear()
        self.log_message("Сервер останавливается...")
    
    def update_indicator(self, status: bool) -> None:
        """Изменяет индикатор состояния сервера."""
        color = "green" if status else "gray"
        self.indicator_canvas.itemconfig(self.indicator, fill=color)
        self.status_label.config(text="Статус: " + ("Включён" if status else "Выключен"))
    
    def create_tray_icon(self) -> None:
        """Создаёт иконку в области уведомлений (трее)."""
        if self.tray_icon is not None:
            return
        # Создаем изображение для иконки
        image = Image.new('RGB', (64, 64), color=(50, 50, 50))
        draw = ImageDraw.Draw(image)
        draw.ellipse((16, 16, 48, 48), fill="green" if self.running else "gray")
        menu = (
            pystray.MenuItem('Открыть', self.restore_window),
            pystray.MenuItem('Включить прокси', self.start_server, enabled=not self.running),
            pystray.MenuItem('Выключить прокси', self.stop_server, enabled=self.running),
            pystray.MenuItem('Выход', self.quit_application)
        )
        self.tray_icon = pystray.Icon(
            "proxy_icon", 
            image, 
            "HTTPS Прокси", 
            menu
        )
        threading.Thread(target=self.tray_icon.run, daemon=True).start()
    
    def minimize_window(self) -> None:
        """Минимизирует окно программы в область уведомлений."""
        if self.minimize_to_tray.get():
            self.root.withdraw()
            self.create_tray_icon()
        else:
            self.on_close()
    
    def restore_window(self) -> None:
        """Восстанавливает основное окно приложения."""
        if self.tray_icon is not None:
            self.tray_icon.stop()
            self.tray_icon = None
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
    
    def quit_application(self) -> None:
        """Завершает работу приложения."""
        try:
            if self.tray_icon is not None:
                self.tray_icon.stop()
                self.tray_icon = None
            self.stop_server()
            self.save_traffic_stats()
            self.root.quit()
            self.root.destroy()
        except Exception as e:
            logger.error(f"Ошибка при завершении приложения: {e}")
        finally:
            os._exit(0)
    
    def on_close(self) -> None:
        """Обработчик события закрытия окна приложения."""
        if self.running:
            if messagebox.askokcancel("Выход", "Прокси-сервер всё ещё работает. Завершить?"):
                self.quit_application()
        else:
            self.quit_application()
    
    @staticmethod
    def main() -> None:
        """Точка входа приложения."""
        root = tk.Tk()
        root.tk.call('tk', 'scaling', 1.5)  # Увеличиваем масштаб интерфейса
        app = ProxyApp(root)
        root.mainloop()

if __name__ == "__main__":
    ProxyApp.main()
