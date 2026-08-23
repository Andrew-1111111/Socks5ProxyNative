# Socks5Proxy

[English](README.md) | **Русский**

Высокопроизводительный SOCKS5-прокси на C++20 (Windows, IOCP) с привязкой исходящего трафика к нужному интерфейсу, встроенным DNS-резолвингом и расширенным логированием.

## Основные возможности

- Полная базовая поддержка SOCKS5 (RFC 1928) для `CONNECT` и `UDP ASSOCIATE`.
- Поддержка адресов `IPv4`, `IPv6` и доменных имен.
- Асинхронная архитектура на IOCP с обработкой большого количества параллельных подключений.
- Ограничение числа одновременных соединений (`MaxConnections`), `0` = без ограничений.
- Привязка исходящих TCP/UDP к заданному IP (`OutputIPAddress`) или имени интерфейса (`OutputInterfaceName`).
- Разрешение доменов через настраиваемый DNS-сервер (`DnsServer`) с кэшем, EDNS, повторными запросами и TCP fallback.
- Поддержка UDP relay с валидацией клиента, фильтрацией источников и idle-timeout.
- Friendly-имена для IP в логах (`IPAddressMappings`) для удобной диагностики.
- Защита от запуска второй копии приложения (single instance guard).
- Корректное завершение по `Ctrl+C` и освобождение ресурсов.
- Консольное логирование с уровнями сообщений.

## Что поддерживается по протоколу

### Поддерживается

- SOCKS5 version `0x05`
- Метод аутентификации `No Authentication` (`0x00`)
- Метод аутентификации `GSSAPI` (`0x01`, RFC 1961 через Windows SSPI Negotiate)
- Метод аутентификации `Username/Password` (`0x02`)
- Команда `CONNECT` (TCP)
- Команда `UDP ASSOCIATE` (UDP relay)
- Сборка UDP FRAG (RFC 1928)
- Адреса IPv4, IPv6, Domain

### Не поддерживается

- Команда BIND

## Требования

- Windows 10/11 (x64)
- Visual Studio 2022+ с рабочей нагрузкой C++, **или** CMake 3.16+ с MSVC
- C++20
- Права администратора (приложение проверяет это на старте и пытается перезапуститься с повышением прав; повышенные права нужны для портов 1–1024 и правил брандмауэра)

## Быстрый запуск

### 1) Сборка (Visual Studio)

```bash
msbuild Socks5Proxy.sln /p:Configuration=Release /p:Platform=x64
```

Или откройте `Socks5Proxy.sln` в Visual Studio и соберите **Release | x64**.

Результат: `bin\x64\Release\Socks5Proxy.exe` (рядом копируется `proxy.json`).

### 1b) Сборка (CMake)

```bash
cmake --preset x64-release
cmake --build --preset x64-release
```

### 2) Настройка `proxy.json`

Файл находится в корне репозитория (`proxy.json`) и копируется рядом с исполняемым файлом при сборке.

Пример:

```json
{
  "ListenIPAddress": "0.0.0.0",
  "ListenPort": 1080,
  "OutputIPAddress": [],
  "OutputInterfaceName": [
    "tap1",
    "tun2"
  ],
  "DnsServer": "8.8.8.8",
  "MaxConnections": 1000,
  "RunDelayS": 0,
  "Username": "",
  "Password": "",
  "IdleTimeoutMs": 60000,
  "ConnectTimeoutMs": 30000,
  "SendTimeoutMs": 30000,
  "ReceiveTimeoutMs": 30000,
  "DnsSendTimeoutMs": 5000,
  "DnsReceiveTimeoutMs": 5000,
  "UdpAssociateIdleTimeoutMs": 120000,
  "SendBufferSize": 262144,
  "ReceiveBufferSize": 262144,
  "BufferSize": 81920,
  "NoDelay": true,
  "KeepAlive": true,
  "LingerEnabled": false,
  "LingerTimeoutSec": 0,
  "TcpKeepAliveTime": 60,
  "TcpKeepAliveInterval": 10,
  "TcpKeepAliveRetryCount": 5,
  "IPAddressMappings": [
    {
      "IPAddress": "192.168.0.10",
      "FriendlyName": "PC_1"
    }
  ]
}
```

### 3) Запуск

Из каталога сборки:

```bash
.\Socks5Proxy.exe
```

Или с явным путём к конфигу:

```bash
.\Socks5Proxy.exe --config "D:\path\to\proxy.json"
```

## Параметры конфигурации

- `ListenIPAddress` — IP-адрес, на котором слушает SOCKS5-сервер (например, 127.0.0.1 или 0.0.0.0).
- `ListenPort` — TCP-порт прослушивания (диапазон: 0–65535). Если выбран порт 0 — система автоматически назначит случайный порт.
- `OutputIPAddress` — список локальных IP-адресов сетевых интерфейсов для исходящих подключений. Приложение выбирает первый доступный рабочий адрес. Может быть пустым.
- `OutputInterfaceName` — список имён сетевых интерфейсов для исходящих подключений. Приложение выбирает первый доступный рабочий интерфейс. Имеет приоритет над `OutputIPAddress`. Может быть пустым.
- `DnsServer` — IP-адрес DNS-сервера для разрешения доменных имён. Может быть пустым.
- `MaxConnections` — максимальное количество одновременных подключений. Значение 0 означает отсутствие ограничения.
- `RunDelayS` — задержка запуска приложения в секундах. Значение 0 означает отсутствие задержки.
- `IPAddressMappings` — массив сопоставлений IP-адресов и человекочитаемых имён для логирования.
- `Username` — имя пользователя для SOCKS5-аутентификации. Не используйте это поле, если нужен `No Authentication`. Может быть пустым.
- `Password` — пароль для SOCKS5-аутентификации. Не используйте это поле, если нужен `No Authentication`. Может быть пустым.
- `EnableGssapi` — предлагать SOCKS5 GSSAPI (`0x01`) через Windows Negotiate/Kerberos/NTLM. По умолчанию `false`.
- `GssapiMaxProtection` — максимальный уровень защиты RFC 1961 после GSSAPI: `1` integrity, `2` confidentiality, `3` selective. По умолчанию `1`.
- `IdleTimeoutMs` / `ConnectTimeoutMs` / `SendTimeoutMs` / `ReceiveTimeoutMs` — таймауты TCP (миллисекунды).
- `DnsSendTimeoutMs` / `DnsReceiveTimeoutMs` — таймауты DNS-запросов.
- `UdpAssociateIdleTimeoutMs` — idle-таймаут UDP ASSOCIATE.
- `SendBufferSize` / `ReceiveBufferSize` / `BufferSize` — размеры буферов сокетов и ретрансляции.
- `NoDelay` — TCP_NODELAY.
- `KeepAlive` / `TcpKeepAliveTime` / `TcpKeepAliveInterval` / `TcpKeepAliveRetryCount` — TCP keepalive.
- `LingerEnabled` / `LingerTimeoutSec` — SO_LINGER.

## Логирование

- Вывод в консоль (уровни в стиле Serilog: information, warning, error).
- Friendly mapping добавляет суффикс вида `(MyHost)` к IP/endpoint в сообщениях логов.

## Безопасность и эксплуатационные особенности

- Таймауты рукопожатия/запросов для защиты от «медленных» клиентов.
- Контроль источников в UDP relay для снижения риска open-proxy abuse.
- Ограничение количества соединений и корректное завершение активных задач при остановке.
- При отсутствии `proxy.json` приложение завершится с понятной ошибкой и подсказкой по `--config`.

## Лицензия

Проект распространяется под лицензией MIT. См. [LICENSE](LICENSE).
