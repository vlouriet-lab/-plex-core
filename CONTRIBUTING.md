# Участие в разработке

Спасибо за интерес к Plex Core! Ниже — инструкция по внесению изменений.

## Требования

- Rust **1.75+** (`rustup update stable`)
- `cargo fmt` и `cargo clippy` без ошибок перед каждым коммитом

## Быстрый старт

```bash
git clone https://github.com/vlouriet-lab/plex-core.git
cd plex-core
cargo build
cargo test
```

## Процесс внесения изменений

1. Создайте ветку от `main`:
   ```bash
   git checkout -b feat/my-feature
   ```
2. Внесите изменения. Убедитесь, что все тесты проходят:
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test
   ```
3. Напишите осмысленный commit-message в стиле `[модуль]: краткое описание`.
4. Откройте Pull Request в `main`. CI проверит форматирование, clippy и тесты автоматически.

## Соглашения

- Публичный API ядра экспортируется через `ffi_*.rs` модули — не добавляйте логику напрямую в `lib.rs`.
- Новые FFI-типы объявляются через `#[uniffi::export]` / `#[derive(uniffi::Record)]`.
- Все операции с БД идут через `storage::Db`; прямые SQL-запросы пишутся только внутри `storage/`.
- Ошибки возвращаются через `PlexError`; не используйте `.unwrap()` в продуктовом коде.
- Секреты оборачиваются в `secrecy::Secret<>` или `zeroize::Zeroizing<>`.

## Сообщить об ошибке

Откройте [issue](https://github.com/vlouriet-lab/plex-core/issues) с шагами воспроизведения,
версией Rust и описанием ожидаемого/фактического поведения.

По вопросам безопасности — см. [SECURITY.md](SECURITY.md).
