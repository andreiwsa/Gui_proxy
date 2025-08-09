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


class ProxyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HTTPS Прокси")
        self.root.geometry("700x550")
        self.root.resizable(True, True)
        self.server_task = None
        self.loop = None
        self.running = False
        self.tasks = []
        self.active_connections = []  # Активные (reader, writer)
        self.log_size = 0
        self.max_log_size = 1024 * 1024  # 1 МБ
        self.BLOCKED = set()  # Используем set для быстрого поиска
        self.tray_icon = None
        self.auto_start = tk.BooleanVar(value=True)  # Автостарт по умолчанию
        self.minimize_to_tray = tk.BooleanVar(value=True)  # Сворачивать в трей по умолчанию
        self.upload_bytes = 0  # Счетчик отправленных байт
        self.download_bytes = 0  # Счетчик полученных байт
        self.last_update_time = 0  # Время последнего обновления статистики

        # === URL для загрузки доменов ===
        self.default_url = "https://github.com/andreiwsa/pacbl/releases/download/v09082025/youtube-domain.txt"

        # === GUI элементы ===
        # URL строка
        url_frame = tk.Frame(self.root)
        url_frame.pack(pady=5, fill=tk.X, padx=10)

        tk.Label(url_frame, text="URL списка доменов:").pack(side=tk.LEFT)

        self.url_entry = tk.Entry(url_frame)
        self.url_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.url_entry.insert(0, self.default_url)

        # 🔧 Добавляем стандартные сочетания клавиш для Entry
        self.setup_entry_bindings(self.url_entry)

        self.load_btn = tk.Button(url_frame, text="Загрузить", command=self.load_blocked_domains)
        self.load_btn.pack(side=tk.LEFT)

        # Поле для добавления своих доменов
        custom_frame = tk.Frame(self.root)
        custom_frame.pack(pady=5, fill=tk.X, padx=10)
        tk.Label(custom_frame, text="Добавить свои домены (по одному или списком):").pack(anchor=tk.W)
        self.custom_text = tk.Text(custom_frame, height=3, width=50)
        self.custom_text.pack(fill=tk.X, pady=2)
        self.add_btn = tk.Button(custom_frame, text="Добавить", command=self.add_custom_domains)
        self.add_btn.pack(anchor=tk.E, padx=2)

        # Настройки
        settings_frame = tk.Frame(self.root)
        settings_frame.pack(pady=5, fill=tk.X, padx=10)
        
        tk.Checkbutton(settings_frame, text="Автостарт прокси", variable=self.auto_start).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(settings_frame, text="Сворачивать в трей", variable=self.minimize_to_tray).pack(side=tk.LEFT, padx=5)

        # Статистика трафика
        traffic_frame = tk.Frame(self.root)
        traffic_frame.pack(pady=5, fill=tk.X, padx=10)
        
        self.upload_label = tk.Label(traffic_frame, text="Отправлено: 0 Б")
        self.upload_label.pack(side=tk.LEFT, padx=5)
        
        self.download_label = tk.Label(traffic_frame, text="Получено: 0 Б")
        self.download_label.pack(side=tk.LEFT, padx=5)
        
        self.reset_traffic_btn = tk.Button(traffic_frame, text="Сбросить", command=self.reset_traffic_stats)
        self.reset_traffic_btn.pack(side=tk.RIGHT, padx=5)

        # Статус
        self.status_frame = tk.Frame(self.root)
        self.status_frame.pack(pady=5)
        self.indicator_canvas = tk.Canvas(self.status_frame, width=20, height=20)
        self.indicator_canvas.pack(side=tk.LEFT)
        self.indicator = self.indicator_canvas.create_oval(5, 5, 15, 15, fill="gray")
        self.status_label = tk.Label(self.status_frame, text="Статус: Выключен", font=("Arial", 10))
        self.status_label.pack(side=tk.LEFT, padx=10)

        # Кнопки управления
        self.btn_frame = tk.Frame(self.root)
        self.btn_frame.pack(pady=5)
        self.start_btn = tk.Button(self.btn_frame, text="Включить", width=10, command=self.start_server)
        self.start_btn.grid(row=0, column=0, padx=5)
        self.stop_btn = tk.Button(self.btn_frame, text="Выключить", width=10, command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=1, padx=5)
        self.exit_btn = tk.Button(self.btn_frame, text="Закрыть", width=10, command=self.on_close)
        self.exit_btn.grid(row=0, column=2, padx=5)

        # Лог
        self.log_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, height=15, state='disabled')
        self.log_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Инициализация
        self.log_message("Готов к работе. Нажмите 'Загрузить', чтобы получить список доменов.")
        
        # Обработка сворачивания в трей
        self.root.protocol("WM_DELETE_WINDOW", self.minimize_window)
        
        # Автозапуск прокси
        if self.auto_start.get():
            self.start_server()

    def setup_entry_bindings(self, entry):
        """Добавляет стандартные сочетания клавиш для Entry: Ctrl+C, Ctrl+V, Ctrl+X, Ctrl+A"""
        entry.bind("<Control-c>", lambda e: self.copy_to_clipboard(entry))
        entry.bind("<Control-v>", lambda e: self.paste_from_clipboard(entry))
        entry.bind("<Control-x>", lambda e: self.cut_to_clipboard(entry))
        entry.bind("<Control-a>", lambda e: entry.select_range(0, 'end'))

    def copy_to_clipboard(self, entry):
        try:
            if entry.selection_present():
                text = entry.selection_get()
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
        except:
            pass

    def paste_from_clipboard(self, entry):
        try:
            text = self.root.clipboard_get()
            if text:
                entry.delete(tk.SEL_FIRST, tk.SEL_LAST if entry.selection_present() else tk.INSERT)
                entry.insert(tk.INSERT, text)
        except:
            pass

    def cut_to_clipboard(self, entry):
        self.copy_to_clipboard(entry)
        if entry.selection_present():
            entry.delete(tk.SEL_FIRST, tk.SEL_LAST)

    def update_traffic_stats(self):
        """Обновляет отображение статистики трафика"""
        def format_bytes(size):
            for unit in ['Б', 'КБ', 'МБ', 'ГБ']:
                if size < 1024:
                    return f"{size:.2f} {unit}"
                size /= 1024
            return f"{size:.2f} ТБ"
        
        self.upload_label.config(text=f"Отправлено: {format_bytes(self.upload_bytes)}")
        self.download_label.config(text=f"Получено: {format_bytes(self.download_bytes)}")

    def reset_traffic_stats(self):
        """Сбрасывает статистику трафика"""
        self.upload_bytes = 0
        self.download_bytes = 0
        self.update_traffic_stats()
        self.log_message("Статистика трафика сброшена")

    def log_message(self, message):
        def append():
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            full_message = f"[{timestamp}] {message}\n"
            self.log_text.config(state='normal')
            self.log_text.insert(tk.END, full_message)
            self.log_text.config(state='disabled')
            self.log_text.see(tk.END)

            self.log_size += len(full_message.encode('utf-8'))

            if self.log_size >= self.max_log_size:
                self.save_log_to_file()

            # Ограничение отображаемого лога
            if len(self.log_text.get("1.0", tk.END)) * 2 > 2 * 1024 * 1024:
                self.log_text.config(state='normal')
                self.log_text.delete("1.0", "end-1c\n")
                self.log_text.config(state='disabled')

        self.root.after(0, append)

    def save_log_to_file(self):
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"proxy_log_{timestamp}.txt"
            content = self.log_text.get("1.0", tk.END)
            with open(filename, "w", encoding="utf-8") as f:
                f.write(content)
            self.log_message(f"Лог сохранён: {filename}")
            self.log_size = 0
        except Exception as e:
            self.log_message(f"Ошибка сохранения лога: {e}")

    def add_custom_domains(self):
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

    def load_blocked_domains(self):
        url = self.url_entry.get().strip()
        if not url:
            self.log_message("URL не указан.")
            return

        # Блокируем кнопку на время загрузки
        self.load_btn.config(state=tk.DISABLED)

        async def async_load():
            try:
                self.log_message("Загрузка доменов с URL...")
                domains = await self.fetch_domains(url)
                self.BLOCKED = domains
                self.log_message(f"✅ Загружено {len(self.BLOCKED)} доменов с {url}")
            except Exception as e:
                self.log_message(f"Ошибка загрузки: {str(e)}")
            finally:
                # Разблокируем кнопку
                self.root.after(0, lambda: self.load_btn.config(state=tk.NORMAL))

        # Запускаем асинхронную задачу в отдельном потоке
        def run_async():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(async_load())
            loop.close()

        threading.Thread(target=run_async, daemon=True).start()

    def get_asyncio_loop(self):
        try:
            return asyncio.get_running_loop()
        except RuntimeError:
            pass
        if self.loop is None:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
        return self.loop

    # === Основная логика сервера ===
    async def pipe(self, reader, writer, is_upload):
        try:
            while not reader.at_eof():
                data = await reader.read(1500)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
                
                # Обновляем статистику трафика
                if is_upload:
                    self.upload_bytes += len(data)
                else:
                    self.download_bytes += len(data)
                
                # Обновляем GUI (не чаще чем раз в 0.5 секунды)
                current_time = asyncio.get_event_loop().time()
                if current_time - self.last_update_time > 0.5:  # Обновляем раз в 0.5 секунды
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
        try:
            head = await local_reader.read(5)
            data = await local_reader.read(1500)
            if all(site not in data for site in self.BLOCKED):
                remote_writer.write(head + data)
                await remote_writer.drain()
                return

            self.log_message("Фрагментация данных...")
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
        except Exception as e:
            self.log_message(f"[FRAGMENT] Ошибка: {e}")

    async def handle_connection(self, local_reader, local_writer):
        addr = local_writer.get_extra_info('peername')
        conn_id = f"{addr[0]}:{addr[1]}"
        self.log_message(f"Подключение: {conn_id}")

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
                self.log_message(f"Некорректный CONNECT: {target} — {e}")
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
            self.log_message(f"Таймаут подключения от {conn_id}")
        except Exception as e:
            self.log_message(f"[HANDLER] Ошибка: {e}")
        finally:
            local_writer.close()
            try:
                await local_writer.wait_closed()
            except:
                pass

    async def run_server(self):
        server = None
        try:
            server = await asyncio.start_server(self.handle_connection, '127.0.0.1', 8881)
            self.log_message("Сервер запущен на 127.0.0.1:8881")
            async with server:
                await server.serve_forever()
        except OSError as e:
            self.log_message(f"[SERVER] Ошибка привязки: {e}")
        except Exception as e:
            self.log_message(f"[SERVER] Ошибка: {e}")
        finally:
            if server:
                server.close()
                await server.wait_closed()

    # === Управление сервером ===
    def start_server(self):
        if not self.running:
            self.running = True
            self.update_indicator(True)
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            threading.Thread(target=self.run_asyncio, daemon=True).start()

    def run_asyncio(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self.run_server())
        except (asyncio.CancelledError, RuntimeError):
            self.log_message("Сервер остановлен.")
        except Exception as e:
            self.log_message(f"Ошибка цикла: {e}")
        finally:
            self.loop.close()
            self.loop = None

    def stop_server(self):
        if self.running:
            self.running = False
            self.update_indicator(False)
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)

            if self.loop and self.loop.is_running():
                for task in self.tasks:
                    task.cancel()
                self.tasks.clear()

                for reader, writer in self.active_connections:
                    if not writer.is_closing():
                        writer.close()
                self.active_connections.clear()

                self.loop.call_soon_threadsafe(self.loop.stop)
                self.log_message("Сервер и все соединения остановлены.")

    def update_indicator(self, status):
        color = "green" if status else "gray"
        self.indicator_canvas.itemconfig(self.indicator, fill=color)
        self.status_label.config(text="Статус: " + ("Включён" if status else "Выключен"))

    # === Трей иконка ===
    def create_tray_icon(self):
        if self.tray_icon is not None:
            return
            
        # Создаем временное изображение для иконки
        image = Image.new('RGB', (64, 64), color='green' if self.running else 'gray')
        
        menu = (
            pystray.MenuItem('Показать', self.restore_window),
            pystray.MenuItem('Включить прокси', self.start_server, enabled=not self.running),
            pystray.MenuItem('Выключить прокси', self.stop_server, enabled=self.running),
            pystray.MenuItem('Выход', self.quit_application)
        )
        
        self.tray_icon = pystray.Icon("proxy_icon", image, "HTTPS Прокси", menu)
        
        # Запускаем иконку в отдельном потоке
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def minimize_window(self):
        if self.minimize_to_tray.get():
            self.root.withdraw()
            self.create_tray_icon()
        else:
            self.on_close()

    def restore_window(self):
        if self.tray_icon is not None:
            self.tray_icon.stop()
            self.tray_icon = None
        self.root.deiconify()

    def quit_application(self):
        if self.tray_icon is not None:
            self.tray_icon.stop()
        self.stop_server()
        self.root.quit()
        os._exit(0)

    def on_close(self):
        if self.running:
            if messagebox.askokcancel("Выход", "Сервер работает. Закрыть?"):
                self.quit_application()
        else:
            self.quit_application()


if __name__ == "__main__":
    root = tk.Tk()
    app = ProxyApp(root)
    root.mainloop()