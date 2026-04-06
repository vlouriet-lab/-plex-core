//! `tests/integration_tests.rs` — интеграционные тесты новых фич ядра (v12).
//!
//! Проверяют:
//! - username-first контакты (MIGRATION_V16);
//! - DHT-анонс по нику и lookup;
//! - пул постоянных соединений.

use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

/// Открывает временную БД для тестов.
fn open_test_db() -> plex_core::storage::Db {
    use secrecy::SecretString;

    static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(1);

    let key = SecretString::new("test-key".to_string());
    let nonce = TEST_DB_COUNTER.fetch_add(1, Ordering::SeqCst);
    let db_path = format!("integration-test-{nonce}.db");
    let _ = fs::remove_file(&db_path);

    plex_core::storage::Db::open(&db_path, &key).expect("open test db")
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

    println!("✓ Username contacts test passed");
}

#[test]
fn test_dht_announce_and_lookup() {
    let db = open_test_db();

    // Имитируемая запись для DHT-анонса
    let payload = serde_json::json!({
        "node_id": "z123abc456def789",
        "username": "bob",
        "display_name": "Bob",
        "relay_url": serde_json::Value::Null,
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
    let v: serde_json::Value = serde_json::from_slice(&found_bytes).expect("decode found value");
    assert_eq!(v["username"].as_str(), Some("bob"));
    assert_eq!(v["node_id"].as_str(), Some("z123abc456def789"));

    println!("✓ DHT announce and lookup test passed");
}

#[test]
fn test_dht_ttl_expiry() {
    let db = open_test_db();

    let payload = serde_json::json!({
        "node_id": "z789xyz",
        "username": "charlie",
        "display_name": "Charlie",
        "relay_url": serde_json::Value::Null,
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

    println!("✓ DHT TTL expiry test passed");
}

#[test]
fn test_connection_pool_basic() {
    use plex_core::connection_pool::ConnectionPool;

    let pool = ConnectionPool::new();

    // Снимок пустого пула
    let status = pool.status_snapshot();
    assert_eq!(status.len(), 0);
    assert_eq!(pool.active_count(), 0);

    println!("✓ Connection pool basic test passed");
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
    let found = db.search_contacts_by_username("user").expect("search");
    assert_eq!(found.len(), 5);

    let found_specific = db.search_contacts_by_username("user2").expect("search");
    assert_eq!(found_specific.len(), 1);
    assert_eq!(found_specific[0].user_id, "peer-2");

    println!("✓ Multiple contacts test passed");
}

#[test]
fn test_username_search_case_insensitive() {
    let db = open_test_db();

    let contact = plex_core::storage::Contact {
        user_id: "peer-test".into(),
        username: "TestUser".into(),
        display_name: "Test User".into(),
        custom_avatar_blob: None,
        trust_level: "Unverified".into(),
        added_at: 100,
    };
    db.upsert_contact(&contact).expect("upsert");

    // Поиск в разных регистрах
    let found_lower = db.search_contacts_by_username("testuser").expect("search");
    assert_eq!(found_lower.len(), 1);

    let found_upper = db.search_contacts_by_username("TESTUSER").expect("search");
    assert_eq!(found_upper.len(), 1);

    let found_mixed = db.search_contacts_by_username("TeSt").expect("search");
    assert_eq!(found_mixed.len(), 1);

    println!("✓ Username search case-insensitive test passed");
}
