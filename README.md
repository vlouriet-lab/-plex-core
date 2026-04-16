# Plex Core

[![CI](https://github.com/vlouriet-lab/-plex-core/actions/workflows/ci.yml/badge.svg)](https://github.com/vlouriet-lab/-plex-core/actions/workflows/ci.yml)

Plex Core — кроссплатформенное ядро для создания децентрализованных приложений с зашифрованной P2P-передачей данных.

Библиотека написана на Rust и предоставляет унифицированный интерфейс через UniFFI для интеграции в Android (Kotlin), iOS (Swift), Desktop и Web-сервисы.

## Стек

| Слой          | Технология                                     |
|---------------|------------------------------------------------|
| Transport     | `iroh` — MagicSock (QUIC + NAT traversal)      |
| Relay/WAN     | Community DERP серверы iroh (бесплатно)        |
| LAN Discovery | `LocalSwarmDiscovery` (mDNS-like)              |
| Storage       | `rusqlite` + SQLCipher (AES-256)               |
| Msg Crypto    | X3DH + Double Ratchet (ChaCha20-Poly1305)      |
| FFI           | UniFFI 0.28 → Kotlin + Swift                   |
| Async         | Tokio multi-thread runtime                     |

## Структура

<details>
<summary>Нажмите для просмотра структуры проекта</summary>

```
plex-core/
├── Cargo.toml
├── build.rs
├── tests/
│   └── integration_tests.rs      # интеграционные тесты
└── src/
    ├── lib.rs                     # UniFFI entry + PlexNode bootstrap + init_node()
    │
    ├── — Криптография —
    ├── crypto.rs                  # Double Ratchet + Zeroize
    ├── x3dh.rs                    # X3DH Extended Triple Diffie-Hellman
    │
    ├── — Хранилище —
    ├── storage.rs                 # SQLCipher root module + event-log + миграции
    ├── storage/
    │   ├── events.rs              # append-only log + DAG/frontier/backfill
    │   ├── projection_events.rs   # typed projection events (PLEXPJ prefix + serde JSON)
    │   ├── ratchet.rs             # Double Ratchet session persistence
    │   ├── chat_messages.rs       # local chat index + unread/read + chunked media
    │   └── delivery_dht.rs        # DHT cache + outbox/delivery persistence
    │
    ├── — Сеть и транспорт —
    ├── network.rs                 # iroh transport + discovery + QUIC routing
    ├── transport.rs               # transport abstraction + route selection
    ├── bridge.rs                  # bridge protocol (обход цензуры, WebSocket/TLS)
    ├── connection_pool.rs         # пул постоянных P2P-соединений
    │
    ├── — Протоколы —
    ├── sync_protocol.rs           # sync rounds / request-response
    ├── dht.rs                     # DHT публикация/поиск/кэш
    ├── message_router.rs          # маршрутизация исходящих сообщений + backoff
    ├── events.rs                  # типы доменных событий
    ├── transfer.rs                # file transfer protocol
    ├── relay_reputation.rs        # репутация relay-узлов
    │
    ├── — Звонки и медиа —
    ├── calls.rs                   # call signaling types
    ├── call_state.rs              # call state machine
    ├── call_media.rs              # in-memory media-plane call session model
    ├── chat_protocol.rs           # chat envelope protocol (text/photo/file/voice/video + receipts)
    ├── mesh_handoff.rs            # mesh sync handoff (BLE/Wi-Fi Direct/side-load)
    │
    ├── — Метрики —
    ├── metrics.rs                 # runtime metrics
    │
    └── — FFI-слой (UniFFI → Kotlin / Swift) —
        ├── ffi_bridge.rs          # bridge FFI API
        ├── ffi_calls.rs           # call signaling/state FFI API
        ├── ffi_call_media.rs      # call media-plane FFI API
        ├── ffi_chat.rs            # chat/media/read-receipt FFI API
        ├── ffi_crypto.rs          # ratchet/crypto/event-log FFI API
        ├── ffi_dht.rs             # DHT FFI API
        ├── ffi_identity.rs        # identity/trust FFI API
        ├── ffi_mesh.rs            # mesh sync/handoff/discovery FFI API
        ├── ffi_message_router.rs  # message router FFI API
        ├── ffi_metrics.rs         # metrics FFI API
        ├── ffi_outbox.rs          # outbox/delivery FFI API + dispatch loop
        ├── ffi_profile.rs         # profile/contact/relay FFI API
        ├── ffi_receiver.rs        # inbound message receiver FFI API
        ├── ffi_storage.rs         # projection recovery FFI API
        ├── ffi_sync.rs            # sync FFI API
        ├── ffi_transfer.rs        # file transfer FFI API
        ├── ffi_x3dh.rs            # X3DH key exchange FFI API
        └── bin/
            └── uniffi_bindgen.rs  # генератор Kotlin/Swift байндингов
```

</details>

  ## Что уже реализовано на первом этапе

  - `init_node(db_key)` открывает SQLCipher БД и поднимает один `iroh::Endpoint`.
  - Network слой начал переход к transport abstraction: route selection и capabilities inventory вынесены отдельно от sync/storage.
  - Добавлен local mesh discovery seam: Android/платформенный слой может репортить BLE/Wi-Fi Direct пиров в ядро без переписывания sync-пайплайна.
  - Фоновые сетевые задачи стартуют автоматически при инициализации узла.
  - LAN discovery логирует найденные peer NodeID через `Endpoint::discovery_stream()`.
  - Входящие QUIC-соединения принимаются в отдельном фоне.
  - FFI-модуль звонков вынесен из `lib.rs` в `ffi_calls.rs` для снижения God Object эффекта.
  - FFI-модуль local mesh/sync handoff вынесен из `lib.rs` в `ffi_mesh.rs` для дополнительной декомпозиции.
  - FFI-модуль identity/trust вынесен из `lib.rs` в `ffi_identity.rs` для декомпозиции verification-политик.
  - FFI-модуль outbox/delivery вынесен из `lib.rs` в `ffi_outbox.rs` (типы, 8 методов, фоновый dispatch loop).
  - FFI-модуль profile/contact/relay вынесен из `lib.rs` в `ffi_profile.rs` (3 типа, 12 методов, relay-репутация).
  - FFI-модуль ratchet/crypto/event-log вынесен в `ffi_crypto.rs` (10 методов + `ensure_ratchet_session_loaded`).
  - FFI-модуль DHT вынесен в `ffi_dht.rs` (3 метода, `DhtMaintenanceReport`). `lib.rs` теперь содержит только bootstrap/init и core-инфраструктуру.
  - Хранилище формализовано как two-layer model: immutable `event_log` + mutable projection tables для быстрых query/API.
  - Добавлен механизм projection recovery: `storage/projection_events.rs` + `ffi_storage.rs`. Typed projection events (magic prefix `PLEXPJ\x01` + JSON) хранятся в event_log и могут быть применены идемпотентно для восстановления projection-таблиц (`identity_registrations`, `verification_anchors`, `users`, `relay_nodes`) после сбоя.
  - Добавлен Android-shell-ready chat/media слой: `chat_protocol.rs` + `ffi_chat.rs` + storage migrations V8/V9 (`chat_messages` + `chat_media_chunks`). Поддержаны text/photo/file/voice note/video note сообщения, ingest входящего ciphertext, локальные notification hints, read receipts, список диалогов и chunked media retrieval.
  - Добавлен media-plane контракт звонков для Android call UI: `call_media.rs` + `ffi_call_media.rs` (route/audio/video/speaker/camera/network quality state).
  - QR-обмен контактами поддерживается через экспорт/import contact JSON (`NodeID + relay + direct addresses`).
  - При каждом P2P-соединении запускается двусторонняя синхронизация event log через QUIC bi-stream.
  - Каждое событие подписывается локальным Ed25519 ключом узла и проверяется перед записью и применением sync.
  - Парольный KDF использует Argon2id; message crypto реализовано через Double Ratchet.
  - Для Android/iOS есть lifecycle-хук `notify_network_change()`.

  ## Публичный API ядра

  <details>
  <summary>Нажмите для просмотра полного списка методов</summary>

    - `init_node(data_dir: String, db_key: String)`
    Фоновые сетевые задачи стартуют автоматически.
  - `node_id()` — возвращает текущий NodeID.
  - `ffi_contract_info()` — возвращает версию FFI-контракта и список поддерживаемых typed error variants/capabilities.
  - `core_health_snapshot()` — возвращает компактный runtime-health snapshot (events, in-memory sessions, latest hash).
  - `export_contact()` — возвращает структуру contact data для QR/UI.
  - `export_contact_json()` — возвращает contact data в JSON для QR-кода.
  - `transport_inventory()` — возвращает активные transport backend'ы и их capabilities для UI/policy-слоя.
  - `report_local_mesh_peer(peer_id, medium, endpoint_hint, signal_strength, last_seen_at)` — регистрирует найденного local mesh пира из платформенного слоя.
  - `list_local_mesh_peers()` — возвращает текущий in-memory registry local mesh discovery.
  - `prune_local_mesh_peers(older_than)` — удаляет устаревшие mesh discovery entries.
  - `export_mesh_sync_bundle(max_events)` — сериализует transport-neutral sync bundle для local mesh / file handoff / side-load сценариев.
  - `export_mesh_sync_bundle_bounded(max_events, max_bytes)` — экспортирует sync bundle, ужатый под byte budget.
  - `import_mesh_sync_bundle(bundle_json)` — применяет transport-neutral sync bundle и возвращает счетчики импортированных сущностей.
  - `prepare_mesh_handoff_bundle(max_events, chunk_size)` — разбивает sync bundle на offer + чанки для BLE/Wi-Fi Direct/side-load handoff.
  - `prepare_mesh_handoff_bundle_bounded(max_events, max_bytes, preferred_chunk_size, max_chunk_size, target_chunks)` — готовит handoff с byte budget и adaptive chunk sizing.
  - `accept_mesh_handoff_offer(offer)` — создает приемную in-memory session для входящего handoff.
  - `ingest_mesh_handoff_chunk(chunk)` — добавляет chunk и возвращает прогресс сборки.
  - `missing_mesh_handoff_chunks(session_id)` — возвращает индексы недостающих chunk'ов для resume.
  - `mesh_handoff_progress(session_id)` — возвращает текущий прогресс resumable handoff-сессии.
  - `request_mesh_handoff_retransmit(session_id)` — формирует явный retransmit request со списком недостающих chunk'ов.
  - `select_mesh_handoff_retransmit_chunks(prepared, request)` — выбирает только запрошенные чанки для selective retransmit.
  - `commit_mesh_handoff_session(session_id)` — собирает bundle, проверяет checksum и импортирует его.
  - `discard_mesh_handoff_session(session_id)` — отменяет незавершенную handoff-сессию.
  - `prune_expired_mesh_handoff_sessions(older_than)` — очищает устаревшие in-memory handoff-сессии по last_updated_at.
  - `send_call_signal(to_peer_id, call_id, signal_type, payload)` — отправляет зашифрованный signaling пакет звонка через outbox delivery.
  - `decode_call_signal_payload(payload)` — декодирует plaintext signaling пакета звонка после расшифрования.
  - `apply_incoming_call_signal(payload)` — применяет входящий signaling payload к локальной call state machine.
  - `mark_call_reconnecting(call_id)` — переводит активный звонок в reconnecting при потере media-path.
  - `get_call_session(call_id)` / `list_call_sessions()` — состояние одной/всех звонковых сессий.
  - `call_maintenance_tick(stale_after_secs, prune_terminal_after_secs)` — timeout и GC звонковых сессий.
  - `add_peer_manual(node_id, addr)` — ручное подключение по NodeID и адресу.
  - `add_peer_from_contact_json(contact_json)` — подключение по QR contact JSON.
  - `append_local_event(payload)` — добавляет локальное событие в append-only log.
  - `create_profile(username, display_name, avatar_data)` — создает/обновляет мой публичный профиль.
  - `update_profile(display_name)` — обновляет display name моего профиля.
  - `get_my_profile()` — возвращает мой профиль.
  - `get_profile(user_id)` — возвращает профиль по user_id.
  - `lookup_profile_by_username(username)` — локальный lookup профиля по username.
  - `add_contact(user_id, username, display_name)` — добавляет локальный контакт (username обязателен).
  - `list_contacts()` — возвращает список локальных контактов.
  - `search_contacts_by_username(query)` — ищет локальные контакты по username (substring match, max 50).
  - `remove_contact(user_id)` — удаляет локальный контакт.
  - `profile_announce(ttl_secs)` — публикует профиль в DHT по ключу `acct:<username_normalized>`.
  - `username_lookup(username)` — ищет пира в DHT по username и возвращает `DiscoveredPeerRecord`.
  - `connection_pool_status()` — возвращает диагностический снимок пула постоянных соединений.
  - `connection_pool_active_count()` — возвращает число активных живых соединений в пуле.
  - `register_as_relay_node()` — регистрирует текущий узел как relay.
  - `get_relay_nodes()` — возвращает известные relay nodes с репутацией.
  - `select_best_relay()` — выбирает лучший relay по локальной policy.
  - `update_relay_reputation(node_id, success)` — обновляет score relay.
  - `get_relay_uptime(node_id)` — возвращает uptime relay в процентах.
  - `heartbeat_relay_node(node_id)` — обновляет heartbeat relay-узла.
  - `deactivate_relay_node(node_id)` — деактивирует relay в локальном реестре.
  - `publish_to_dht(key, value)` — публикует значение в локальный DHT-кэш с дефолтным TTL.
  - `publish_to_dht_with_ttl(key, value, ttl_secs)` — публикует значение в DHT-кэш с заданным TTL.
  - `lookup_dht(key)` — читает значение из DHT-кэша, если TTL не истек.
  - `dht_maintenance_tick()` — maintenance-хук: очистка expired записей и продление скоро истекающих.
  - DHT sync: активные DHT-записи реплицируются между пирами через основной sync-протокол.
  - `queue_encrypted_message_for_peer(peer_id, plaintext)` — кладет зашифрованное сообщение в надежный outbox.
  - `outbox_next_batch(limit)` — возвращает сообщения, готовые к отправке/retry.
  - `outbox_mark_sent(message_id)` — помечает outbox сообщение как отправленное.
  - `outbox_mark_failed(message_id, error_text, retry_after_secs)` — помечает отправку как failed и планирует retry.
  - `outbox_mark_failed_backoff(message_id, error_text)` — помечает failed и рассчитывает retry по exponential backoff.
  - `outbox_ack_delivered(peer_id, message_id)` — фиксирует delivery ack и завершает доставку.
  - `register_inbound_message_once(peer_id, message_id)` — idempotency dedup для входящих сообщений.
  - `delivery_maintenance_tick()` — удаляет старые dedup/receipt записи по retention policy.
  - Delivery receipts sync: подтверждения доставки реплицируются между пирами через основной sync-протокол.
  - `send_text_message(peer_id, text)` — отправляет текстовое сообщение и индексирует его в локальном чате.
  - `send_photo_message(peer_id, file_name, mime_type, width, height, bytes)` — отправляет фото-сообщение.
  - `send_file_message(peer_id, file_name, mime_type, bytes)` — отправляет файл.
  - `send_voice_note(peer_id, file_name, mime_type, duration_ms, bytes)` — отправляет голосовое сообщение.
  - `send_video_note(peer_id, file_name, mime_type, width, height, duration_ms, bytes)` — отправляет видеосообщение (кружочек).
  - `ingest_incoming_chat_ciphertext(peer_id, transport_message_id, ciphertext)` — дешифрует входящее transport-сообщение, применяет chat message/read receipt и возвращает hint для UI-уведомления.
  - `mark_chat_message_read_and_notify(peer_id, message_id)` — помечает сообщение прочитанным и отправляет read receipt собеседнику.
  - `list_chat_messages(peer_id, limit, before_ts)` — возвращает историю диалога.
  - `unread_chat_count(peer_id)` — возвращает число непрочитанных входящих сообщений по диалогу.
  - `list_chat_dialogs(limit, offset)` — возвращает список диалогов (последнее сообщение + unread counter).
  - `get_chat_message_media(message_id)` — возвращает media bytes для сообщения (inline или собранные из chunks).
  - `upsert_call_media_session(...)` / `get_call_media_session(call_id)` / `list_call_media_sessions()` / `remove_call_media_session(call_id)` — media-plane состояние звонка для Android call UI.
  - Outbox worker: фоновый dispatcher автоматически продвигает queued/failed сообщения и применяет backoff+dead-letter policy.
  - `ratchet_drop_session(peer_id)` — удаляет ratchet-сессию пира из памяти и БД.
  - `register_peer_identity(peer_id, identity_commitment)` — подписывает и сохраняет identity registration.
  - `verify_peer_identity(peer_id, expected_commitment)` — проверяет регистрацию личности по подписи.
  - `record_verification_anchor(peer_id, event_hash, chain, tx_id, confirmations)` — сохраняет blockchain anchor.
  - `peer_verification_status(peer_id)` — возвращает агрегированный статус регистрации и anchor-верификации.
  - `is_peer_verified(peer_id, min_confirmations, allowed_chains)` — policy-check верифицированности пира.
  - `peer_trust_level(peer_id, policy)` — возвращает trust-level (`Unverified|Registered|Anchored|Trusted`) с учетом freshness/confirmations/chain policy.
  - `latest_event_hash()` — возвращает хеш последнего локального события.
  - `event_count()` — возвращает количество локальных событий.
  - `notify_network_change()` — сигнализирует transport-слою о смене сети.

</details>

## Быстрый старт

```bash
# 1. Установить Rust 1.75+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Собрать ядро
cd plex-core
cargo build --release

# 3. Запустить тесты
cargo test

# Windows: если linker не может открыть test .exe из-за file lock,
# используйте отдельный target-dir
cargo test --target-dir target-phaseD-run

# 4. Сгенерировать Kotlin-байндинги
cargo run --bin uniffi-bindgen generate \
  --library ./target/debug/libplex_core.so \
  --language kotlin \
  --out-dir ./bindings/kotlin

# 5. Сгенерировать Swift-байндинги
cargo run --bin uniffi-bindgen generate \
  --library ./target/debug/libplex_core.dylib \
  --language swift \
  --out-dir ./bindings/swift
```

## Для Android (cross-компиляция)

```bash
rustup target add aarch64-linux-android
cargo build --target aarch64-linux-android --release
```

## Для iOS

```bash
rustup target add aarch64-apple-ios
cargo build --target aarch64-apple-ios --release
```

## Лицензия

Проект распространяется под лицензией **GNU GPL v3**. См. файл [LICENSE](LICENSE) для подробностей.

---
© 2026 Plex Core Team.
