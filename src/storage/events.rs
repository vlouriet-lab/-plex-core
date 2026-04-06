use super::*;

impl Db {
    /// Вставляет новое событие в append-only лог.
    pub fn insert_event(&self, event: &Event) -> Result<(), PlexError> {
        validate_event(event)?;

        self.conn()?
            .execute(
                "INSERT OR IGNORE INTO event_log (id, author, payload, signature, prev_hash, ts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    event.id,
                    event.author,
                    event.payload,
                    event.signature,
                    event.prev_hash,
                    event.ts,
                ],
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;
        Ok(())
    }

    /// Вставляет пачку событий в одной транзакции.
    pub fn insert_events(&self, events: &[Event]) -> Result<usize, PlexError> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;
        let mut inserted = 0usize;

        {
            let mut stmt = tx
                .prepare(
                    "INSERT OR IGNORE INTO event_log (id, author, payload, signature, prev_hash, ts)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

            for event in events {
                validate_event(event)?;

                inserted += stmt
                    .execute(params![
                        event.id,
                        event.author,
                        event.payload,
                        event.signature,
                        event.prev_hash,
                        event.ts,
                    ])
                    .map_err(|e| PlexError::Storage { msg: e.to_string() })?;
            }
        }

        tx.commit()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;
        Ok(inserted)
    }

    /// Создаёт и сохраняет локальное событие автора.
    pub fn append_local_event(
        &self,
        author_secret: &SecretKey,
        payload: &[u8],
    ) -> Result<Event, PlexError> {
        let author = author_secret.public().to_string();
        let prev_hash = self.latest_event_hash()?;
        let ts = current_unix_micros()?;
        let id = compute_event_id(&author, payload, prev_hash.as_deref(), ts);
        let event = Event {
            id: id.clone(),
            author,
            payload: payload.to_vec(),
            signature: sign_event_id(author_secret, &id),
            prev_hash,
            ts,
        };

        self.insert_event(&event)?;
        Ok(event)
    }

    /// Возвращает все события после заданного хеша (для sync-логики).
    pub fn events_after(&self, after_hash: Option<&str>) -> Result<Vec<Event>, PlexError> {
        let conn = self.conn()?;

        match after_hash {
            Some(hash) => {
                let mut stmt = conn
                    .prepare(
                        "WITH RECURSIVE chain(id, author, payload, signature, prev_hash, ts) AS (
                             SELECT id, author, payload, signature, prev_hash, ts
                             FROM event_log
                             WHERE prev_hash = ?1

                             UNION ALL

                             SELECT e.id, e.author, e.payload, e.signature, e.prev_hash, e.ts
                             FROM event_log e
                             INNER JOIN chain c ON e.prev_hash = c.id
                         )
                         SELECT id, author, payload, signature, prev_hash, ts
                         FROM chain
                         ORDER BY ts ASC",
                    )
                    .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

                collect_events(&mut stmt, params![hash])
            }
            None => {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, author, payload, signature, prev_hash, ts
                         FROM event_log
                         ORDER BY ts ASC",
                    )
                    .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

                collect_events(&mut stmt, [])
            }
        }
    }

    /// Возвращает хеш последнего события в логе.
    pub fn latest_event_hash(&self) -> Result<Option<String>, PlexError> {
        let heads = self.frontier_hashes()?;
        Ok(heads.first().cloned())
    }

    /// Возвращает все события в порядке временных меток.
    pub fn all_events(&self) -> Result<Vec<Event>, PlexError> {
        self.events_after(None)
    }

    /// Возвращает события, написанные конкретным автором (author = NodeID пира),
    /// которые ещё НЕ зарегистрированы в `inbound_message_dedup`.
    ///
    /// Используется `process_incoming_events_from_peer`:
    /// - Anti-join с `inbound_message_dedup` гарантирует, что при переписке длиннее
    ///   `limit` событий каждый новый вызов обнаруживает только необработанные записи,
    ///   а не возвращает одни и те же первые N старых событий.
    /// - После фикса dedup-регистрации (register-after-apply) сюда попадают только
    ///   события с ошибкой декриптования (ретрай) или ещё не начатые.
    pub fn events_by_author(&self, author: &str, limit: usize) -> Result<Vec<Event>, PlexError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, author, payload, signature, prev_hash, ts
                 FROM event_log
                 WHERE author = ?1
                   AND id NOT IN (
                       SELECT message_id FROM inbound_message_dedup WHERE peer_id = ?1
                   )
                 ORDER BY ts ASC
                 LIMIT ?2",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        collect_events(&mut stmt, params![author, limit as i64])
    }

    /// Возвращает все известные хеши событий.
    #[allow(dead_code)]
    pub fn all_event_ids(&self) -> Result<Vec<String>, PlexError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT id FROM event_log")
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(rows)
    }

    /// Возвращает вершины всех текущих веток (heads),
    /// отсортированные по глубине цепочки, затем по времени.
    pub fn frontier_hashes(&self) -> Result<Vec<String>, PlexError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "WITH RECURSIVE walk(id, depth) AS (
                     SELECT id, 1 FROM event_log WHERE prev_hash IS NULL

                     UNION ALL

                     SELECT e.id, walk.depth + 1
                     FROM event_log e
                     INNER JOIN walk ON e.prev_hash = walk.id
                 ),
                 max_depth AS (
                     SELECT id, MAX(depth) AS depth
                     FROM walk
                     GROUP BY id
                 )
                 SELECT e.id
                 FROM event_log e
                 LEFT JOIN event_log child ON child.prev_hash = e.id
                 LEFT JOIN max_depth d ON d.id = e.id
                 WHERE child.id IS NULL
                 ORDER BY COALESCE(d.depth, 0) DESC, e.ts DESC, e.id DESC",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(rows)
    }

    /// Возвращает события, которых нет в known_hashes, в детерминированном порядке.
    pub fn events_excluding(
        &self,
        known_hashes: &[String],
        limit: usize,
    ) -> Result<Vec<Event>, PlexError> {
        let known = known_hashes.iter().cloned().collect::<HashSet<_>>();
        let mut events = self
            .all_events()?
            .into_iter()
            .filter(|event| !known.contains(&event.id))
            .collect::<Vec<_>>();

        if events.len() > limit {
            events.truncate(limit);
        }

        Ok(events)
    }

    /// Возвращает запрошенные события и их предков для backfill.
    pub fn events_with_ancestors(
        &self,
        need_hashes: &[String],
        limit: usize,
    ) -> Result<Vec<Event>, PlexError> {
        if need_hashes.is_empty() {
            return Ok(Vec::new());
        }

        let all_events = self.all_events()?;
        let mut by_id = HashMap::with_capacity(all_events.len());
        for event in all_events {
            by_id.insert(event.id.clone(), event);
        }

        let mut queue = VecDeque::from(need_hashes.to_vec());
        let mut seen = HashSet::new();
        let mut selected = Vec::new();

        while let Some(hash) = queue.pop_front() {
            if !seen.insert(hash.clone()) {
                continue;
            }

            let Some(event) = by_id.get(&hash) else {
                continue;
            };

            selected.push(event.clone());

            if let Some(prev_hash) = &event.prev_hash {
                queue.push_back(prev_hash.clone());
            }
        }

        selected.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.id.cmp(&b.id)));
        if selected.len() > limit {
            selected.truncate(limit);
        }

        Ok(selected)
    }

    /// Возвращает prev_hash, для которых в локальной БД еще нет событий-предков.
    pub fn orphan_prev_hashes(&self, limit: usize) -> Result<Vec<String>, PlexError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT e.prev_hash
                 FROM event_log e
                 LEFT JOIN event_log parent ON parent.id = e.prev_hash
                 WHERE e.prev_hash IS NOT NULL
                   AND parent.id IS NULL
                 ORDER BY e.ts ASC
                 LIMIT ?1",
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        let rows = stmt
            .query_map([limit as i64], |row| row.get(0))
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(rows)
    }

    /// Возвращает true, если событие с указанным хешем уже есть в БД.
    pub fn has_event(&self, event_id: &str) -> Result<bool, PlexError> {
        let exists = self
            .conn()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM event_log WHERE id = ?1)",
                [event_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|e| PlexError::Storage { msg: e.to_string() })?;

        Ok(exists != 0)
    }
}

pub(crate) fn validate_event(event: &Event) -> Result<(), PlexError> {
    if event.author.trim().is_empty() {
        return Err(PlexError::Storage {
            msg: "Event author must not be empty".into(),
        });
    }

    if event.ts < 0 {
        return Err(PlexError::Storage {
            msg: format!("Event timestamp must be non-negative, got {}", event.ts),
        });
    }

    let expected_id = compute_event_id(
        &event.author,
        &event.payload,
        event.prev_hash.as_deref(),
        event.ts,
    );

    if event.id != expected_id {
        return Err(PlexError::Storage {
            msg: format!(
                "Event id mismatch: expected {}, got {}",
                expected_id, event.id,
            ),
        });
    }

    let author_key: PublicKey = event.author.parse().map_err(|e| PlexError::Storage {
        msg: format!("Invalid event author public key '{}': {e}", event.author),
    })?;

    let signature = Signature::from_slice(&event.signature).map_err(|e| PlexError::Storage {
        msg: format!("Invalid event signature bytes: {e}"),
    })?;

    author_key
        .verify(event.id.as_bytes(), &signature)
        .map_err(|e| PlexError::Storage {
            msg: format!("Event signature verification failed: {e}"),
        })?;

    Ok(())
}

pub(crate) fn sign_event_id(author_secret: &SecretKey, event_id: &str) -> Vec<u8> {
    author_secret.sign(event_id.as_bytes()).to_bytes().to_vec()
}

fn collect_events<P: rusqlite::Params>(
    stmt: &mut rusqlite::Statement<'_>,
    params: P,
) -> Result<Vec<Event>, PlexError> {
    stmt.query_map(params, |row| {
        Ok(Event {
            id: row.get(0)?,
            author: row.get(1)?,
            payload: row.get(2)?,
            signature: row.get(3)?,
            prev_hash: row.get(4)?,
            ts: row.get(5)?,
        })
    })
    .map_err(|e| PlexError::Storage { msg: e.to_string() })?
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| PlexError::Storage { msg: e.to_string() })
}

/// Одно событие в детерминированном append-only логе.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Event {
    pub id: String,
    pub author: String,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub prev_hash: Option<String>,
    pub ts: i64,
}

pub(crate) fn compute_event_id(
    author: &str,
    payload: &[u8],
    prev_hash: Option<&str>,
    ts: i64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(author.as_bytes());
    hasher.update(payload);
    hasher.update(prev_hash.unwrap_or_default().as_bytes());
    hasher.update(ts.to_le_bytes());
    encode_hex(&hasher.finalize())
}

pub(crate) const MIGRATION_V1: &str = "
CREATE TABLE IF NOT EXISTS schema_version (
    version  INTEGER NOT NULL
);

INSERT INTO schema_version (version)
SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);

CREATE TABLE IF NOT EXISTS event_log (
    id        TEXT    NOT NULL PRIMARY KEY,
    author    TEXT    NOT NULL,
    payload   BLOB    NOT NULL,
    signature BLOB    NOT NULL,
    prev_hash TEXT,
    ts        INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_event_log_ts     ON event_log (ts);
CREATE INDEX IF NOT EXISTS idx_event_log_author ON event_log (author);
";
