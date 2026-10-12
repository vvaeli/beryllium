# Beryllium

Быстрый и надёжный прокси/VPN-клиент для **Arch Linux, macOS и Windows** с графическим интерфейсом, TUI и CLI.

> 🚧 **Статус: в разработке.** Готового релиза пока нет, план работ — в [ROADMAP.md](ROADMAP.md).

> ⚠️ **Windows не проверен на реальной системе.** Код собирается и проходит тесты в CI, но TUN (wintun), системный прокси (WinINet через помощника в сессии пользователя) и служба Windows ещё не проверялись вручную на Windows 10/11. Нужен тест на живой машине (ROADMAP 6.2, 6.9). macOS и Linux проверены, TUN на macOS работает от root.

## Зачем

Существующие клиенты на macOS периодически теряют соединение после сна или смены сети, и его приходится переподключать вручную. В Beryllium надёжность — главная цель: клиент не доверяет тому, что туннель жив, а постоянно это проверяет и сам восстанавливает соединение.

## Возможности

- **Любые протоколы из подписки:** VLESS (Reality, XHTTP и др.), VMess, Trojan, Shadowsocks, Hysteria2, TUIC, WireGuard, **AmneziaWG**
- **Несколько ядер:** [sing-box](https://github.com/SagerNet/sing-box), [Xray](https://github.com/XTLS/Xray-core) и [mihomo](https://github.com/MetaCubeX/mihomo) (для AmneziaWG). Для каждого сервера автоматически выбирается подходящее ядро, его можно переопределить вручную
- **Три режима:** TUN (весь трафик системы), системный прокси и только локальный прокси, переключаются на лету без переподключения к другому серверу
- **Переживает сон и смену сети:** ждёт готовности сети после пробуждения, сбрасывает мёртвые соединения и DNS-кеш; постоянный watchdog с автоматическим восстановлением и переключением на резервный сервер
- **Маршрутизация:** пресеты «всё через VPN», «RU напрямую», «только заблокированное», пользовательские правила, раздельное туннелирование по приложениям. **Профили Happ/INCY** (заголовок `routing`, ссылки `happ://routing/…`, `incy://routing/…`) применяются автоматически, geo-файлы `geoip.dat`/`geosite.dat` поддерживаются
- **DNS без утечек:** DoH через туннель, перехват DNS в TUN, IPv6 блокируется по умолчанию, FakeIP по желанию
- **Любой Linux:** Arch, Debian, Fedora, Artix и др.; systemd, OpenRC, runit, dinit, s6; GNOME, KDE, Hyprland, niri, sway
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
Служба ставится под любую init-систему: `sudo berylliumd install` сам определит systemd, OpenRC, runit, dinit или s6.

На Hyprland, niri, sway и других окружениях без общей настройки прокси используйте режим TUN (`beryl mode tun`): режим системного прокси там действует только на приложения, запущенные после подключения.

## Быстрый старт

**GUI:** запустите Beryllium, вставьте ссылку на подписку и нажмите «Подключиться».

**CLI:**
```sh
beryl sub add 'https://…/sub/…' --name main   # добавить подписку
beryl servers                                  # список серверов
beryl connect <server>                         # подключиться (имя, часть имени или ID)
beryl connect --auto --mode tun                # самый быстрый сервер, весь трафик системы
beryl mode proxy                               # сменить режим на лету: tun | proxy | local
beryl status --watch                           # статус, ядро, локальный прокси, трафик
beryl test                                     # проверить связь через туннель
beryl disconnect
beryl sub qr <id>                              # QR-код подписки прямо в терминале
beryl routing                                  # профили маршрутизации (пресеты, от провайдера, свои)
beryl routing import 'happ://routing/onadd/…'  # импорт профиля Happ/INCY
beryl rules add process Telegram proxy         # своё правило: приложение через VPN
beryl dns --ipv6 block                         # настройки DNS
eval "$(beryl env)"                            # прокси для текущего терминала
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
