# Smoke 💨

<p>
  <a href="https://github.com/Akdered/Smoke/releases/latest"><img src="https://img.shields.io/github/v/release/Akdered/Smoke?style=flat-square&color=brightgreen&label=Release" alt="Latest Release"></a>
  <a href="https://github.com/Akdered/Smoke/releases"><img src="https://img.shields.io/github/downloads/Akdered/Smoke/total?style=flat-square&color=blue&label=Downloads" alt="Downloads"></a>
  <img src="https://img.shields.io/badge/Rust-Tokio%20Async-orange?style=flat-square&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-0078D6?style=flat-square&logo=windows" alt="Windows">
  <img src="https://img.shields.io/badge/Admin%20%2F%20Drivers-Not%20Required-success?style=flat-square" alt="Zero-Admin">
  <a href="https://github.com/Akdered/Smoke/blob/main/README.md"><img src="https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square" alt="MIT License"></a>
</p>

Высокопроизводительный, легковесный **Zero-Admin DPI-bypass прокси** для Windows, написанный на **Rust** (Tokio).

Разработан по принципу **«Запустил — и всё работает» (Zero-Config)**: обходит блокировки и замедления ТСПУ (YouTube, Discord, X/Twitter, Rutracker и др.) **без установки драйверов (`WinDivert`)**, **без прав администратора** и **без сторонних DLL** (один файл `~3.8 МБ`).

```
   _____                     __          
  / ___/ ____ ___   ____    / /__ ___    
  \__ \ / __ `__ \ / __ \  / //_// _ \   
 ___/ // / / / / // /_/ / / ,<  /  __/   
/____//_/ /_/ /_/ \____/ /_/|_| \___/    
             by Akdered
    High-Performance DPI Bypass Engine v0.6.0
```

---

## 🚀 Быстрый старт (для обычного пользователя)

1. Скачайте **`smoke.exe`** из раздела [Releases](https://github.com/Akdered/Smoke/releases).
2. Запустите двойным кликом.
3. **Готово!** YouTube, Discord и заблокированные сайты работают сразу во всей системе.

> При закрытии окна (нажатием на `[X]`, `Ctrl + C` или даже при принудительном снятии задачи в Диспетчере задач) фоновый сторож `Watchdog` мгновенно возвращает сетевые настройки Windows в исходное состояние, так что интернет никогда не «сломается».

---

## ⚡ Ключевые возможности v0.6.0

### 1. 🛡 User-Space `FakeTls` (через `TransmitFile`) + `TlsRecMicroSni` + `TlsRecOobSni`
- **Настоящие `Fake`-пакеты без драйвера (`FakeTls4` / `FakeTls6`)**: с помощью zero-copy механизма `TransmitFile` ядра Windows Smoke отправляет фальшивый `ClientHello` (`www.vk.com`) с `TTL=4/6`, который долетает до ТСПУ провайдера, обеляет TCP-сессию и сгорает до целевого сервера, после чего ядро ретранслирует настоящий `ClientHello` через 3-сегментный Fast Retransmit.
- **Микро-дробление SNI (`TlsRecMicroSni`)**: разрезает `ClientHello` на 4 TLS-рекорда с вырезанием 1-байтного микро-рекорда ровно из центра имени домена и смещением TCP-сегментов (разрушает сигнатуру даже коротких доменов вроде `x.com` без зависимости от `TTL` и домашних GPON-роутеров).
- **Односегментный `TlsRecOobSni`**: склеивает Urgent-байт (`MSG_OOB`) прямо в конец первой половины SNI, сбивая потоковый сборщик ТСПУ на 1 байт.

### 2. 🎯 Принцип «Не навреди» (`Direct-First`) и прямой пропуск `.ru`
- Российские ресурсы (`*.ru`, `*.рф`, VK, Yandex, Ozon, Avito, Госуслуги, банки и серверы загрузки Steam) исключены на уровне ОС (`ProxyOverride`) и ядра прокси — они идут **напрямую с нулевой задержкой**.
- Для обычных зарубежных сайтов сначала проверяется прямое соединение (`None`), а обход включается только при реальной блокировке или обрыве потока на 16–24 КБ (`16KB Freeze Detector`).

### 3. 🔒 Защита от флаппинга (Anti-Flapping v2) и быстрый отсев мёртвых GGC-узлов
- Мёртвые кэш-серверы `rr1---sn-*.googlevideo.com` отбрасываются за `1.4 сек` вместо `10 сек`, позволяя плееру YouTube и YouTube Music мгновенно переключаться на живой CDN без буферизации и без ложной смены рабочей стратегии.
- Обученные стратегии сохраняются по имени в `%LOCALAPPDATA%\Smoke\cache_v2.json`.

### 4. 🐕 Неубиваемый выход с процессом-сторожем (`Watchdog`)
- При старте запускается микро-сторож (`0% CPU`), который следит за дескриптором процесса в ядре Windows и гарантированно очищает `ProxyEnable` и `ProxyServer` даже после `Диспетчер задач -> Снять задачу`.

> 💡 **Если в голосовом канале Discord висит «Подключение RTC» (RTC Connecting):**
> 1. В Discord откройте: **Настройки пользователя** -> **Голос и видео**.
> 2. Прокрутите вниз и выключите: **«Включить приоритет качества обслуживания (QoS)»**.
> 3. Если проблема сохраняется, попросите админа сервера сменить регион голосового канала на **«Central Europe»** или **«Rotterdam»**.

---

## 🛠 Арсенал техник обхода (17 алгоритмов)

| № | Стратегия | Описание механизма | Рекомендуется для |
|---|-----------|--------------------|-------------------|
| 1 | **`TlsRecMicroSni`** | 4 TLS-рекорда с вырезанием 1-байтного микро-рекорда из центра SNI + смещенный TCP-сплит | Универсальный №1 (Ростелеком, GPON-роутеры, короткие домены `x.com`) |
| 2 | **`TlsRecordFrag2`** | 2-звенный TLS-рекорд + разрез TCP-потока внутри SNI | Discord, Cloudflare, высокая совместимость со всеми CDN |
| 3 | **`TlsRecOobSni`** | Фрагментация TLS-рекорда + односегментный TCP Urgent (`MSG_OOB`) байт в SNI | Сбивает потоковые TCP+TLS сборщики ТСПУ без привязки к TTL |
| 4 | **`FakeTls4`** | User-Space `Fake` ClientHello (`www.vk.com`) через zero-copy `TransmitFile` + `MapViewOfFile` (`TTL=3`) | Пробивает жесткие белые списки ТСПУ без драйвера WinDivert |
| 5 | **`FakeTls6`** | User-Space `Fake` ClientHello (`www.vk.com`) с `TTL=5` + 3-сегментный Fast Retransmit | Сети с двойным NAT и глубокой маршрутизацией |
| 6 | **`TlsRecordFragSni`** | Разноуровневый разрез TLS-рекорда ровно по центру SNI + смещенный TCP-сплит | Силат, EcoFilter |
| 7 | **`OobSni`** | Односегментная инъекция TCP Urgent Pointer (`MSG_OOB`) в конец первой половины SNI | Сигнатурный DPI |
| 8 | **`TcpSplitSni`** | Чистый TCP-сплит точно по центру имени хоста SNI | Google Global Cache (GGC), низкий MTU |
| 9 | **`TlsRecordFrag`** | Разрез ClientHello на 3–4 TLS-рекорда (RFC 8446) | Классический ШПД |
| 10 | **`Disorder3`** | 1-й байт с `TTL=3` + 3-сегментный RFC 5681 Fast Retransmit | Обход за домашними GPON-модемами и BRAS |
| 11 | **`Disorder2`** | 1-й байт с `TTL=2` + 3-сегментный Fast Retransmit | Сети за домашним Wi-Fi роутером |
| 12 | **`Disorder1`** | 1-й байт с `TTL=1` + 3-сегментный Fast Retransmit | Прямой кабель / USB-модемы |
| 13 | **`DisorderSni2`** | Disorder-разрез до середины SNI с `TTL=2` | ТСПУ за домашним NAT |
| 14 | **`DisorderSni`** | Disorder-разрез до середины SNI с `TTL=1` | Мобильные операторы |
| 15 | **`Combo`** | Мульти-рекордная фрагментация SNI + TCP Disorder | Упорные комбинированные блокировки |
| 16 | **`TcpSplit2`** | Двойной TCP-сплит после 2-го байта (`0x16 0x03`) и центра SNI | Классический мульти-сплит |
| 17 | **`TcpSplit1`** | TCP-сплит после 1-го байта | Базовая сегментация |
| — | **`None`** | Прямая передача без нарезки (`Direct-First`) | Автоматически для `.ru` и незаблокированных сайтов |

---

## ⚙ Параметры командной строки

```text
Usage: smoke.exe [OPTIONS]

Options:
  -b, --bind <BIND>          Адрес и порт для запуска прокси [default: 127.0.0.1:1080]
  -p, --preset <PRESET>      Пресет обхода [default: auto] 
                             [possible values: auto, rtk, mobile, discord, ultra]
  -s, --strategy <STRATEGY>  Принудительно зафиксировать одну стратегию
  -m, --minimized            Скрыть окно консоли и работать в фоновом режиме
      --scan                 Запустить предварительный бенчмарк сети перед стартом
      --no-sysproxy          Не включать системный прокси Windows (только SOCKS5/HTTP на 1080)
      --clean                Экстренно очистить системный прокси Windows и выйти
  -v, --verbose              Подробный вывод логов (DEBUG)
  -h, --help                 Показать справку
  -V, --version              Показать версию
```

### Примеры:

1. **Обычный запуск (рекомендуется всем)**:
   ```powershell
   smoke.exe
   ```

2. **Запуск в скрытом/фоновом режиме**:
   ```powershell
   smoke.exe --minimized
   ```

3. **Запуск с принудительной отправкой фейкового ClientHello (`TransmitFile`)**:
   ```powershell
   smoke.exe --strategy fake-tls4
   ```

4. **Экстренный сброс настроек сети Windows**:
   ```powershell
   smoke.exe --clean
   ```

---

## 📦 Сборка из исходников

```powershell
# Клонирование репозитория
git clone https://github.com/Akdered/Smoke.git
cd Smoke

# Сборка оптимизированного релизного бинарника (fat LTO)
cargo build --release
```

Готовый файл: `target/release/smoke.exe` (статическая линковка, размер ~3.8 МБ, без сторонних DLL).

---

## 📄 Лицензия

MIT License © 2026 Akdered
