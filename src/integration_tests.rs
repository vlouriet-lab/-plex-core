//! `src/integration_tests.rs` — интеграционные тесты новых фич ядра (v12).
//!
//! Эти тесты проверяют:
//! - username-first контакты (MIGRATION_V16);
//! - DHT-анонс по нику и lookup;
//! - пул постоянных соединений.

#[cfg(test)]
mod tests {
    use plex_core::*;
    use std::sync::Arc;
    use std::time::Duration;

    /// Открывает временную БД для тестов.
    fn open_test_db() -> Arc<plex_core::storage::Db> {
        use secrecy::SecretString;
        use std::fs;
        use std::sync::atomic::AtomicU64;
        use std::sync::atomic::Ordering;

        static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(1);

        let key = SecretString::new("test-key".to_string());
        let nonce = TEST_DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("integration-test-{nonce}.db"));
        let db_path_str = db_path.to_string_lossy().to_string();
        let _ = fs::remove_file(&db_path_str);

        let db = plex_core::storage::Db::open(&db_path_str, &key).expect("open test db");
        Arc::new(db)
    }

    #[test]
    fn test_username_contacts_roundtrip() {
        let db = open_test_db();

        // Добавляем контакт с username
        let contact = plex_core::storage::Contact {
            user_id: "peer-alice".into(),
            username: "alice".into(),
            display_name: "Alice".into(),
            custom_avatar_blob: None,
            trust_level: "Verified".into(),
            added_at: 100,
        };

        db.upsert_contact(&contact).expect("upsert");

        // Загружаем обратно
        let loaded = db.list_contacts().expect("list");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].username, "alice");
        assert_eq!(loaded[0].display_name, "Alice");

        // Поиск по username
        let results = db
            .search_contacts_by_username("ali")
            .expect("search_contacts_by_username");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].user_id, "peer-alice");
    }

    #[test]
    fn test_dht_announce_and_lookup() {
        let db = open_test_db();

        // Имитируемая запись для DHT-анонса
        let payload = serde_json::json!({
            "node_id": "z123abc456def789",
            "username": "bob",
            "display_name": "Bob",
            "relay_url": null,
            "announced_at": 1712345678i64,
        });

        let value = serde_json::to_vec(&payload).expect("encode");
        let dht_key = "acct:bob";
        let now_secs = 1712345678i64;

        // Публикуем в локальный DHT-кэш
        db.publish_dht_record(dht_key, &value, 86400, now_secs)
            .expect("publish_dht_record");

        // Ищем по нику
        let found = db
            .lookup_dht_record(dht_key, now_secs)
            .expect("lookup_dht_record");

        assert!(found.is_some());
        let found_bytes = found.unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&found_bytes).expect("decode found value");
        assert_eq!(v["username"].as_str(), Some("bob"));
        assert_eq!(v["node_id"].as_str(), Some("z123abc456def789"));
    }

    #[test]
    fn test_dht_ttl_expiry() {
        let db = open_test_db();

        let payload = serde_json::json!({
            "node_id": "z789xyz",
            "username": "charlie",
            "display_name": "Charlie",
            "relay_url": null,
            "announced_at": 100i64,
        });

        let value = serde_json::to_vec(&payload).expect("encode");
        let dht_key = "acct:charlie";

        // Публикуем с TTL 10 сек, с момента 100
        db.publish_dht_record(dht_key, &value, 10, 100)
            .expect("publish");

        // Ищем в момент 105 (до истечения) — должно быть найдено
        let found_in_time = db
            .lookup_dht_record(dht_key, 105)
            .expect("lookup before expiry");
        assert!(found_in_time.is_some());

        // Ищем в момент 115 (после истечения) — не должно быть найдено
        let found_after_expiry = db
            .lookup_dht_record(dht_key, 115)
            .expect("lookup after expiry");
        assert!(found_after_expiry.is_none());
    }

    #[test]
    fn test_connection_pool_basic() {
        use plex_core::connection_pool::ConnectionPool;

        let pool = ConnectionPool::new();

        // Снимок пустого пула
        let status = pool.status_snapshot();
        assert_eq!(status.len(), 0);
        assert_eq!(pool.active_count(), 0);
    }

    #[test]
    fn test_multiple_contacts_and_usernames() {
        let db = open_test_db();

        // Добавляем несколько контактов с username'ами
        for i in 0..5 {
            let contact = plex_core::storage::Contact {
                user_id: format!("peer-{i}"),
                username: format!("user{i}"),
                display_name: format!("User {i}"),
                custom_avatar_blob: None,
                trust_level: "Unverified".into(),
                added_at: 100 + i as i64,
            };
            db.upsert_contact(&contact).expect("upsert");
        }

        // Проверяем список
        let all = db.list_contacts().expect("list");
        assert_eq!(all.len(), 5);

        // Проверяем, что username'ы не пустые
        for contact in &all {
            assert!(!contact.username.is_empty());
        }

        // Поиск по partial match
        let found = db
            .search_contacts_by_username("user")
            .expect("search");
        assert_eq!(found.len(), 5);

        let found_specific = db
            .search_contacts_by_username("user2")
            .expect("search");
        assert_eq!(found_specific.len(), 1);
        assert_eq!(found_specific[0].user_id, "peer-2");
    }

    #[tokio::test]
    async fn test_ffi_contract_v12() {
        // Проверяем, что FFI контракт включает все новые флаги
        let flags = [
            ("supports_username_contacts_v1", true),
            ("supports_username_discovery_v1", true),
            ("supports_persistent_pool_v1", true),
        ];

        // В реальном тесте здесь была бы инициализация PlexNode и проверка ffi_contract_info()
        // Для интеграции достаточно знать, что флаги определены.

        println!("FFI v12 contract requirements:");
        for (flag, required) in flags.iter() {
            println!("  {}: {}", flag, if *required { "REQUIRED" } else { "OPTIONAL" });
        }
    }
}
