# Установка

Одна команда ставит сервер в любой MCP-клиент прямо из репозитория —
публиковать пакет никуда не нужно:

```
uvx --from git+https://github.com/votsie/ssh-mcp ssh-mcp
```

Единственное требование — [uv](https://docs.astral.sh/uv/). Он сам поставит
нужный Python и зависимости в изолированное окружение; ничего в систему не
устанавливается.

```bash
# Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
# Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Проверить, что всё сходится, до всякой настройки клиента:

```bash
uvx --from git+https://github.com/votsie/ssh-mcp ssh-mcp
```

Команда должна замолчать и ждать ввода — это и есть работающий stdio-сервер.
Выход по Ctrl+C.

---

## Claude Code

Плагином, вместе с тремя скиллами:

```bash
claude plugin marketplace add https://github.com/votsie/ssh-mcp
claude plugin install ssh-mcp@ssh-mcp
```

Либо только MCP-сервером, без скиллов:

```bash
claude mcp add --scope user ssh -- uvx --from git+https://github.com/votsie/ssh-mcp ssh-mcp
```

После установки нужен перезапуск Claude Code.

## Codex CLI

В `~/.codex/config.toml`:

```toml
[mcp_servers.ssh]
command = "uvx"
args = ["--from", "git+https://github.com/votsie/ssh-mcp", "ssh-mcp"]
```

## Cursor

В `~/.cursor/mcp.json` (глобально) или `.cursor/mcp.json` в проекте:

```json
{
  "mcpServers": {
    "ssh": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/votsie/ssh-mcp", "ssh-mcp"]
    }
  }
}
```

## Claude Desktop

В `claude_desktop_config.json` (Настройки → Разработчик → Изменить конфигурацию)
— тот же блок `mcpServers`, что и для Cursor.

## Windsurf

В `~/.codeium/windsurf/mcp_config.json` — тот же блок `mcpServers`.

## Zed

В `settings.json`:

```json
{
  "context_servers": {
    "ssh": {
      "command": {
        "path": "uvx",
        "args": ["--from", "git+https://github.com/votsie/ssh-mcp", "ssh-mcp"]
      }
    }
  }
}
```

## Любой другой клиент

Клиенту нужно ровно одно: команда, запускающая stdio-сервер.

| Поле | Значение |
|---|---|
| команда | `uvx` |
| аргументы | `--from`, `git+https://github.com/votsie/ssh-mcp`, `ssh-mcp` |
| транспорт | stdio |

---

## Без uv

```bash
pipx run --spec git+https://github.com/votsie/ssh-mcp ssh-mcp
# или обычная установка, после которой команда просто `ssh-mcp`
pip install git+https://github.com/votsie/ssh-mcp
```

## Версии и обновление

`uvx` кэширует окружение по URL, поэтому новый коммит сам собой не подтянется:

```bash
uvx --refresh --from git+https://github.com/votsie/ssh-mcp ssh-mcp
```

Прибить версию к тегу — надёжнее для боевого использования:

```
git+https://github.com/votsie/ssh-mcp@v0.2.0
```

## Настройки

Задаются переменными окружения в блоке `env` конфигурации клиента.

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `SSHM_HOME` | `~/.ssh-mcp` | Каталог состояния: доступы, known_hosts, память, журнал |
| `SSHM_CONNECT_TIMEOUT` | `20` | Таймаут коннекта, баннера и аутентификации |
| `SSHM_CMD_TIMEOUT` | `300` | Таймаут команды по умолчанию |
| `SSHM_SHELL_TTL` | `1800` | Простой, после которого интерактивная сессия закрывается |
| `SSHM_KEEPALIVE` | `30` | Период keepalive |
| `SSHM_DEBUG` | — | Подробный лог в `~/.ssh-mcp/logs/` |

## Руководства для агентов без скиллов

Скиллы понимает только Claude Code. Всем остальным тот же материал доступен
двумя способами, и делать для этого ничего не нужно:

* **инструкции сервера** уходят клиенту при подключении — там три правила,
  нарушение которых стоит дороже всего;
* **`ssh_guide(topic)`** — обычный инструмент, отдаёт полное руководство по
  темам `servers`, `interactive`, `ops`. Видно любому агенту.

Дополнительно те же тексты объявлены подсказками MCP (`ssh-servers`,
`ssh-interactive`, `ssh-ops`) — на случай клиентов, которые их показывают.

## Проверка после установки

Попросите агента вызвать `ssh_status()`. Ответ вида
`{"servers": [], "connections": [], "sessions": [], "tunnels": []}`
означает, что сервер поднялся и готов к работе.

## Если не заработало

**«uvx: command not found», сервер не стартует.** Самая частая причина, и почти
всегда — не в самом uv. Клиент запускает сервер не из вашей оболочки, а из
своего процесса, и `PATH` там другой: у приложений с graphical-интерфейсом
(Claude Desktop на macOS — типичный случай) в нём нет ни `~/.local/bin`, ни
`~/.cargo/bin`. Лечится абсолютным путём:

```bash
command -v uvx    # Linux / macOS
where uvx         # Windows
```

Полученный путь и подставьте вместо `uvx` в поле `command`.

**Сервер стартует, но инструментов не видно.** Проверьте, что клиент вообще
поднял процесс, — почти у всех есть журнал MCP. Собственный лог сервера лежит
в `~/.ssh-mcp/logs/ssh-mcp.log`, подробности включаются переменной
`SSHM_DEBUG=1`.

**Обновление не подтягивается.** `uvx` кэширует окружение по URL. Добавьте
`--refresh` в аргументы один раз, затем уберите обратно.

**Первый запуск долгий.** uv скачивает Python и зависимости; дальше стартует
из кэша за доли секунды. Если клиент рвёт соединение по таймауту, выполните
команду из INSTALL один раз руками — окружение осядет в кэше.
