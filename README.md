# Beryllium

Быстрый и надёжный прокси/VPN-клиент для **Arch Linux, macOS и Windows** с графическим интерфейсом, TUI и CLI.

> 🚧 **Статус: в разработке.** Готового релиза пока нет, план работ — в [ROADMAP.md](ROADMAP.md).

## Зачем

Существующие клиенты на macOS периодически теряют соединение после сна или смены сети, и его приходится переподключать вручную. В Beryllium надёжность — главная цель: клиент не доверяет тому, что туннель жив, а постоянно это проверяет и сам восстанавливает соединение.

## Возможности

- **Любые протоколы из подписки:** VLESS (Reality, XHTTP и др.), VMess, Trojan, Shadowsocks, Hysteria2, TUIC, WireGuard, **AmneziaWG**
- **Несколько ядер:** [sing-box](https://github.com/SagerNet/sing-box), [Xray](https://github.com/XTLS/Xray-core) и [mihomo](https://github.com/MetaCubeX/mihomo) (для AmneziaWG). Для каждого сервера автоматически выбирается подходящее ядро, его можно переопределить вручную
- **Два режима:** TUN (весь трафик системы) и системный прокси, переключаются на лету
- **Переживает сон и смену сети:** ждёт готовности сети после пробуждения, сбрасывает мёртвые соединения и DNS-кеш; постоянный watchdog с автоматическим восстановлением и переключением на резервный сервер
- **Маршрутизация:** RU-сайты и локальная сеть напрямую, пользовательские правила, раздельное туннелирование по приложениям. **Правила от провайдера в формате Happ/INCY** (заголовок `routing`, ссылки `happ://routing/…`) применяются автоматически
- **Три интерфейса:** GUI с треем, TUI для терминала, CLI для скриптов
- **Без встроенных серверов:** подписка добавляется пользователем
- **QR-коды:** покажите подписку или сервер QR-кодом, чтобы быстро добавить на телефон. Импорт с экрана или из картинки

## Архитектура

```
┌──────────┐ ┌──────────┐ ┌──────────┐
│   GUI    │ │   TUI    │ │   CLI    │   без прав администратора
│ (Tauri)  │ │  (Go)    │ │  (Go)    │
└────┬─────┘ └────┬─────┘ └────┬─────┘
     └────────────┼────────────┘
                  │ gRPC: unix socket / named pipe
         ┌────────▼─────────┐
         │   berylliumd     │   служба: systemd / launchd / Windows Service
         │  подписки,       │
         │  watchdog,       │
         │  сон/сеть        │
         └───┬─────────┬────┘
             │         │       отдельные процессы
       ┌─────▼───┐ ┌───▼───────────┐
       │sing-box │→│ Xray / mihomo │  sing-box держит TUN, остальные ядра — через SOCKS
       └─────────┘ └───────────────┘
```

- **`berylliumd`** — привилегированный демон: управляет ядрами, подписками и туннелем. VPN продолжает работать при закрытом GUI.
- **`beryl`** — CLI и TUI в одном бинарнике.
- **Beryllium.app / .exe / нативные пакеты Linux** — графический клиент с треем.

## Установка

> Пакеты появятся с первым релизом (`v0.1.0`).

| ОС | Способ |
|---|---|
| Arch Linux | `yay -S beryllium-bin` (GUI) / `yay -S beryllium-cli` (только CLI/TUI), или `sudo pacman -U beryllium-*.pkg.tar.zst` из [Releases](../../releases) |
| Debian / Ubuntu, Fedora | `.deb` / `.rpm` из [Releases](../../releases) |
| macOS | `brew install --cask vvaeli/tap/beryllium` или `.dmg` из [Releases](../../releases) |
| Windows | установщик `.exe` из [Releases](../../releases), `winget` / `scoop` |

**macOS:** приложение не подписано сертификатом Apple. При первом запуске откройте его через контекстное меню → «Открыть» или выполните:
```sh
xattr -dr com.apple.quarantine /Applications/Beryllium.app
```

**Linux:** для работы без root добавьте себя в группу `beryllium` и перелогиньтесь:
```sh
sudo usermod -aG beryllium $USER
```

## Быстрый старт

**GUI:** запустите Beryllium, вставьте ссылку на подписку и нажмите «Подключиться».

**CLI:**
```sh
beryl sub add 'https://…/sub/…' --name main   # добавить подписку
beryl servers                                  # список серверов
beryl connect --auto                           # подключиться к лучшему серверу
beryl connect <server> --mode tun              # конкретный сервер в режиме TUN
beryl status --watch                           # статус в реальном времени
beryl disconnect
beryl sub qr <id>                              # QR-код подписки прямо в терминале
```

**TUI:**
```sh
beryl tui        # или просто `beryl`
```

## Сборка из исходников

Требования: Go ≥ 1.23, Rust (stable), Node.js ≥ 20, [buf](https://buf.build), [just](https://github.com/casey/just).

```sh
just fetch-cores   # скачать sing-box и Xray (с проверкой SHA-256)
just gen           # сгенерировать код из proto
just build         # собрать демон и CLI
just gui-dev       # GUI в режиме разработки
just test          # тесты
```

## Лицензия

[GPL-3.0](LICENSE). Ядра распространяются под своими лицензиями: sing-box и mihomo — GPL-3.0, Xray — MPL-2.0.
