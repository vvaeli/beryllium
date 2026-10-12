# Участие в разработке

## Порядок работы

- План — в [ROADMAP.md](ROADMAP.md). Берите шаги по порядку и отмечайте `[x]` в том же PR.
- Коммиты по [Conventional Commits](https://www.conventionalcommits.org/) с номером шага: `feat(sub): vless parser [4.5]`.
- Перед PR: `just lint` и `just test`.

## Окружение

Go (версия из `go.mod`), Rust stable, Node.js ≥ 20, [just](https://github.com/casey/just), [buf](https://buf.build), [golangci-lint](https://golangci-lint.run) v2, [lefthook](https://github.com/evilmartians/lefthook) (`lefthook install` для pre-commit хуков).

## Секреты

Никогда не коммитьте и не прикладывайте к issue ссылки подписок, UUID и пароли серверов. Фикстуры для тестов — только обезличенные.
