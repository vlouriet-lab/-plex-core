use std::time::{SystemTime, UNIX_EPOCH};

use tracing::warn;

use crate::{chat_protocol, storage, PlexError, PlexNode};

/// Максимальное количество входящих сообщений от одного пира за 60 сек.
/// Защищает от DoS атак через флудинг запросами ingest.
const MAX_INGEST_PER_PEER_PER_MINUTE: u32 = 120;
/// Максимальный размер медиа-вложения в исходящем сообщении (32 MB).
const MAX_SEND_MEDIA_BYTES: usize = 32 * 1024 * 1024;
/// Максимальное число peer-записей в rate-limit HashMap.
/// При достижении предела эвиктируются записи с истёкшим окном (>60 сек);
/// если и после этого HashMap переполнен — новый пир отклоняется по rate limit.
const MAX_INGEST_PEERS_TRACKED: usize = 4096;

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum ChatMessageKindRecord {
    Text,
    Photo,
    File,
    VoiceNote,
    VideoNote,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatMediaMetaRecord {
    pub file_name: String,
    pub mime_type: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatMessageRecord {
    pub message_id: String,
    pub peer_id: String,
    pub transport_message_id: Option<String>,
    pub is_outgoing: bool,
    pub kind: ChatMessageKindRecord,
    pub text: Option<String>,
    pub media_meta: Option<ChatMediaMetaRecord>,
    pub media_bytes: Option<Vec<u8>>,
    pub status: String,
    pub created_at: i64,
    pub sent_at: Option<i64>,
    pub delivered_at: Option<i64>,
    pub read_at: Option<i64>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatDialogSummaryRecord {
    pub peer_id: String,
    pub last_message_id: String,
    pub last_kind: ChatMessageKindRecord,
    pub last_text_preview: Option<String>,
    pub last_status: String,
    pub last_created_at: i64,
    pub unread_count: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct IncomingChatIngestReport {
    pub is_duplicate: bool,
    pub is_read_receipt: bool,
    pub should_notify_user: bool,
    pub message: Option<ChatMessageRecord>,
}

/// Результат массовой обработки входящих событий из event log пира.
#[derive(Debug, Clone, uniffi::Record)]
pub struct IngestFromEventLogReport {
    /// Peer, события которого обрабатывались.
    pub peer_id: String,
    /// Сколько событий было просмотрено в event_log.
    pub events_examined: u64,
    /// Новых сообщений/receipt успешно добавлено в chat_messages.
    pub ingested_new: u64,
    /// Уже известных (дубликаты) или пропущенных projection-событий.
    pub duplicates_skipped: u64,
    /// Событий, при обработке которых возникла ошибка (расшифровка/валидация).
    pub errors: u64,
}

#[uniffi::export]
impl PlexNode {
    pub fn send_text_message(
        &self,
        peer_id: String,
        text: String,
    ) -> Result<ChatMessageRecord, PlexError> {
        self.send_chat_message_internal(
            peer_id,
            chat_protocol::ChatMessageKind::Text,
            Some(text),
            None,
            None,
        )
    }

    pub fn send_photo_message(
        &self,
        peer_id: String,
        file_name: String,
        mime_type: String,
        width: Option<u32>,
        height: Option<u32>,
        bytes: Vec<u8>,
    ) -> Result<ChatMessageRecord, PlexError> {
        self.send_chat_message_internal(
            peer_id,
            chat_protocol::ChatMessageKind::Photo,
            None,
            Some(chat_protocol::ChatMediaMeta {
                file_name,
                mime_type,
                width,
                height,
                duration_ms: None,
            }),
            Some(bytes),
        )
    }

    pub fn send_file_message(
        &self,
        peer_id: String,
        file_name: String,
        mime_type: String,
        bytes: Vec<u8>,
    ) -> Result<ChatMessageRecord, PlexError> {
        self.send_chat_message_internal(
            peer_id,
            chat_protocol::ChatMessageKind::File,
            None,
            Some(chat_protocol::ChatMediaMeta {
                file_name,
                mime_type,
                width: None,
                height: None,
                duration_ms: None,
            }),
            Some(bytes),
        )
    }

    pub fn send_voice_note(
        &self,
        peer_id: String,
        file_name: String,
        mime_type: String,
        duration_ms: u64,
        bytes: Vec<u8>,
    ) -> Result<ChatMessageRecord, PlexError> {
        self.send_chat_message_internal(
            peer_id,
            chat_protocol::ChatMessageKind::VoiceNote,
            None,
            Some(chat_protocol::ChatMediaMeta {
                file_name,
                mime_type,
                width: None,
                height: None,
                duration_ms: Some(duration_ms),
            }),
            Some(bytes),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send_video_note(
        &self,
        peer_id: String,
        file_name: String,
        mime_type: String,
        width: Option<u32>,
        height: Option<u32>,
        duration_ms: u64,
        bytes: Vec<u8>,
    ) -> Result<ChatMessageRecord, PlexError> {
        self.send_chat_message_internal(
            peer_id,
            chat_protocol::ChatMessageKind::VideoNote,
            None,
            Some(chat_protocol::ChatMediaMeta {
                file_name,
                mime_type,
                width,
                height,
                duration_ms: Some(duration_ms),
            }),
            Some(bytes),
        )
    }

    /// Дешифрует входящий transport payload, применяет сообщение или read-receipt,
    /// и возвращает hint для Android-уведомления.
    pub fn ingest_incoming_chat_ciphertext(
        &self,
        peer_id: String,
        transport_message_id: String,
        ciphertext: Vec<u8>,
    ) -> Result<IncomingChatIngestReport, PlexError> {
        let now = now_secs()?;

        // ── Rate limiting: не более MAX_INGEST_PER_PEER_PER_MINUTE за 60 с от одного пира ──
        {
            let mut limits = self
                .ingest_rate_limits
                .lock()
                .map_err(|e| PlexError::Internal {
                    msg: format!("ingest_rate_limits mutex poisoned: {e}"),
                })?;

            // C1: Если HashMap переполнен — сначала эвиктируем истёкшие окна (>60 сек).
            if !limits.contains_key(&peer_id) && limits.len() >= MAX_INGEST_PEERS_TRACKED {
                limits.retain(|_, (_, window_start)| now.saturating_sub(*window_start) <= 60);
                if limits.len() >= MAX_INGEST_PEERS_TRACKED {
                    // После очистки всё ещё переполнено — отклоняем новый источник.
                    warn!(
                        peer_id = %peer_id,
                        "[security] ingest rate-limit table full — rejecting new peer"
                    );
                    return Err(PlexError::RateLimit {
                        msg: "Rate limit table full, try again later".to_string(),
                    });
                }
            }

            let entry = limits.entry(peer_id.clone()).or_insert((0u32, now));
            let (count, window_start) = entry;
            if now.saturating_sub(*window_start) > 60 {
                // Новое окно
                *count = 1;
                *window_start = now;
            } else {
                *count = count.saturating_add(1);
                if *count > MAX_INGEST_PER_PEER_PER_MINUTE {
                    warn!(
                        peer_id = %peer_id,
                        count = *count,
                        limit = MAX_INGEST_PER_PEER_PER_MINUTE,
                        "[security] ingest rate limit hit"
                    );
                    self.metrics.inc(&self.metrics.chat_messages_duplicate);
                    return Err(PlexError::RateLimit {
                        msg: format!(
                            "Too many messages from peer {peer_id}: {} in 60s (limit {})",
                            count, MAX_INGEST_PER_PEER_PER_MINUTE
                        ),
                    });
                }
            }
        };

        self.ingest_chat_ciphertext_inner(peer_id, transport_message_id, ciphertext)
    }

    /// Обрабатывает все события из event_log, написанные пиром `peer_id`,
    /// которые ещё не попали в `chat_messages`.
    ///
    /// Вызывается Android-слоем после каждого `on_sync_received(peer_id, n)` —
    /// это замыкает разрыв между `event_log` (sync-сторона) и `chat_messages` (UI-сторона).
    ///
    /// Не использует rate-limit: события уже находятся в локальной аутентифицированной БД.
    pub fn process_incoming_events_from_peer(
        &self,
        peer_id: String,
        limit: u64,
    ) -> Result<IngestFromEventLogReport, PlexError> {
        let events = self.db.events_by_author(&peer_id, limit as usize)?;
        let events_examined = events.len() as u64;
        let mut ingested_new = 0u64;
        let mut duplicates_skipped = 0u64;
        let mut errors = 0u64;

        for event in events {
            // Projection-события (PLEXPJ magic prefix) — не чат, пропускаем.
            if event.payload.starts_with(b"PLEXPJ\x01") {
                duplicates_skipped += 1;
                continue;
            }

            match self.ingest_chat_ciphertext_inner(
                peer_id.clone(),
                event.id.clone(),
                event.payload,
            ) {
                Ok(report) => {
                    if report.is_duplicate {
                        duplicates_skipped += 1;
                    } else {
                        ingested_new += 1;
                    }
                }
                Err(PlexError::Storage { .. }) => {
                    // Transient DB error — не регистрируем, повторим при следующем вызове.
                    errors += 1;
                }
                Err(PlexError::Crypto { ref msg }) if msg.contains("not initialized") => {
                    // X3DH-сессия ещё не принята: DHT-запись пира не успела синхронизироваться
                    // к моменту вызова ingest (гонка между QUIC-connect и фоновым DHT-sync).
                    // Это ВРЕМЕННАЯ ошибка — сессия будет установлена при следующем polling-цикле.
                    // НЕ регистрируем в dedup — событие должно быть обработано повторно.
                    errors += 1;
                }
                Err(_) => {
                    // Постоянная ошибка (Crypto / Validation / Network):
                    // ratchet десинхронизирован или payload поврежден — повтор бессмысленен.
                    // Регистрируем в dedup, чтобы events_by_author больше не возвращал это событие
                    // и не блокировал обработку последующих сообщений от этого пира.
                    if let Ok(now) = now_secs() {
                        let _ = self
                            .db
                            .register_inbound_message_once(&peer_id, &event.id, now);
                    }
                    errors += 1;
                }
            }
        }

        Ok(IngestFromEventLogReport {
            peer_id,
            events_examined,
            ingested_new,
            duplicates_skipped,
            errors,
        })
    }

    /// Помечает сообщение прочитанным локально и отправляет read receipt собеседнику.
    pub fn mark_chat_message_read_and_notify(
        &self,
        peer_id: String,
        message_id: String,
    ) -> Result<bool, PlexError> {
        let now = now_secs()?;

        let Some(existing) = self.db.load_chat_message(&message_id)? else {
            return Err(PlexError::NotFound {
                msg: format!("chat message not found: {message_id}"),
            });
        };

        if existing.peer_id != peer_id {
            return Err(PlexError::Validation {
                msg: format!(
                    "chat peer mismatch for message {}: {} != {}",
                    message_id, existing.peer_id, peer_id
                ),
            });
        }

        let updated = self.db.mark_chat_message_read(&message_id, now)?;
        if !updated {
            return Ok(false);
        }

        let receipt = chat_protocol::ChatReadReceiptPayload {
            protocol: chat_protocol::CHAT_PROTOCOL.to_string(),
            message_id,
            reader_peer_id: self.iroh.node_id().to_string(),
            chat_peer_id: peer_id.clone(),
            read_at: now,
        };

        let payload = chat_protocol::encode_envelope(&chat_protocol::ChatEnvelope::ReadReceipt {
            payload: receipt,
        })?;

        let _ = self.queue_encrypted_message_for_peer(peer_id, payload)?;
        self.metrics.inc(&self.metrics.chat_read_receipts_sent);
        Ok(true)
    }

    pub fn list_chat_messages(
        &self,
        peer_id: String,
        limit: u64,
        before_ts: Option<i64>,
    ) -> Result<Vec<ChatMessageRecord>, PlexError> {
        let rows = self
            .db
            .list_chat_messages(&peer_id, limit as usize, before_ts)?;
        Ok(rows.into_iter().map(to_chat_record).collect())
    }

    pub fn unread_chat_count(&self, peer_id: String) -> Result<u64, PlexError> {
        self.db.count_unread_chat_messages(&peer_id)
    }

    pub fn list_chat_dialogs(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<ChatDialogSummaryRecord>, PlexError> {
        let rows = self.db.list_chat_dialogs(limit as usize, offset as usize)?;

        rows.into_iter()
            .map(to_dialog_record)
            .collect::<Result<Vec<_>, _>>()
    }

    pub fn get_chat_message_media(&self, message_id: String) -> Result<Option<Vec<u8>>, PlexError> {
        self.db.load_chat_media_blob(&message_id)
    }
}

impl PlexNode {
    /// Внутренняя логика ingest без rate-limit.
    ///
    /// Используется двумя путями:
    /// 1. `ingest_incoming_chat_ciphertext` — после прохождения rate-limit.
    /// 2. `process_incoming_events_from_peer` — для событий из локального event_log.
    fn ingest_chat_ciphertext_inner(
        &self,
        peer_id: String,
        transport_message_id: String,
        ciphertext: Vec<u8>,
    ) -> Result<IncomingChatIngestReport, PlexError> {
        let now = now_secs()?;

        // ── Peek (read-only): проверяем дубликат БЕЗ записи в dedup ──────────────────
        // ВАЖНО: register происходит ПОСЛЕ успешного decrypt+apply, чтобы ошибка
        // декриптования не блокировала повторную попытку в следующем sync-цикле.
        let already_seen = self
            .db
            .is_inbound_message_registered(&peer_id, &transport_message_id)?;

        if already_seen {
            self.metrics.inc(&self.metrics.chat_messages_duplicate);
            return Ok(IncomingChatIngestReport {
                is_duplicate: true,
                is_read_receipt: false,
                should_notify_user: false,
                message: None,
            });
        }

        let plaintext = self.decrypt_from_peer(peer_id.clone(), ciphertext)?;
        let envelope = chat_protocol::decode_envelope(&plaintext)?;

        match envelope {
            chat_protocol::ChatEnvelope::ReadReceipt { payload } => {
                if payload.reader_peer_id != peer_id {
                    return Err(PlexError::Validation {
                        msg: format!(
                            "read receipt peer mismatch: {} != {}",
                            payload.reader_peer_id, peer_id
                        ),
                    });
                }
                let _ = self
                    .db
                    .mark_chat_message_read(&payload.message_id, payload.read_at.max(now))?;

                // Регистрируем ПОСЛЕ успешного apply
                let _ =
                    self.db
                        .register_inbound_message_once(&peer_id, &transport_message_id, now)?;

                self.metrics.inc(&self.metrics.chat_read_receipts_received);
                Ok(IncomingChatIngestReport {
                    is_duplicate: false,
                    is_read_receipt: true,
                    should_notify_user: false,
                    message: None,
                })
            }
            chat_protocol::ChatEnvelope::Message { payload } => {
                let local_peer_id = self.iroh.node_id().to_string();
                if payload.to_peer_id != local_peer_id {
                    return Err(PlexError::Validation {
                        msg: format!(
                            "incoming chat target mismatch: {} != {}",
                            payload.to_peer_id, local_peer_id
                        ),
                    });
                }

                if payload.from_peer_id != peer_id {
                    return Err(PlexError::Validation {
                        msg: format!(
                            "incoming chat sender mismatch: {} != {}",
                            payload.from_peer_id, peer_id
                        ),
                    });
                }

                let chat = storage::ChatMessage {
                    message_id: payload.message_id,
                    peer_id: peer_id.clone(),
                    transport_message_id: Some(transport_message_id.clone()),
                    is_outgoing: false,
                    kind: to_kind_string(payload.kind),
                    body_text: payload.text,
                    media_name: payload.media_meta.as_ref().map(|m| m.file_name.clone()),
                    media_mime: payload.media_meta.as_ref().map(|m| m.mime_type.clone()),
                    media_width: payload.media_meta.as_ref().and_then(|m| m.width),
                    media_height: payload.media_meta.as_ref().and_then(|m| m.height),
                    media_duration_ms: payload.media_meta.as_ref().and_then(|m| m.duration_ms),
                    media_size: payload.media_bytes.as_ref().map(|bytes| bytes.len() as i64),
                    media_blob: payload.media_bytes,
                    status: "delivered".into(),
                    created_at: payload.created_at,
                    sent_at: Some(payload.created_at),
                    delivered_at: Some(now),
                    read_at: None,
                    updated_at: now,
                };
                self.db.upsert_chat_message(&chat)?;

                // Регистрируем ПОСЛЕ успешного upsert
                let _ =
                    self.db
                        .register_inbound_message_once(&peer_id, &transport_message_id, now)?;

                self.metrics.inc(&self.metrics.chat_messages_received);
                Ok(IncomingChatIngestReport {
                    is_duplicate: false,
                    is_read_receipt: false,
                    should_notify_user: true,
                    message: Some(to_chat_record(chat)),
                })
            }
        }
    }

    fn send_chat_message_internal(
        &self,
        peer_id: String,
        kind: chat_protocol::ChatMessageKind,
        text: Option<String>,
        media_meta: Option<chat_protocol::ChatMediaMeta>,
        media_bytes: Option<Vec<u8>>,
    ) -> Result<ChatMessageRecord, PlexError> {
        // Проверем размер медиа до любых других действий.
        if let Some(bytes) = &media_bytes {
            if bytes.len() > MAX_SEND_MEDIA_BYTES {
                warn!(
                    peer_id = %peer_id,
                    size = bytes.len(),
                    limit = MAX_SEND_MEDIA_BYTES,
                    "[security] outgoing media too large"
                );
                return Err(PlexError::Validation {
                    msg: format!(
                        "Media payload too large: {} bytes (limit {} bytes / 32 MB)",
                        bytes.len(),
                        MAX_SEND_MEDIA_BYTES
                    ),
                });
            }
        }
        let now = now_secs()?;
        let local_peer_id = self.iroh.node_id().to_string();

        let mut fingerprint = text.clone().unwrap_or_default().into_bytes();
        if let Some(bytes) = &media_bytes {
            fingerprint.extend_from_slice(&bytes[..bytes.len().min(64)]);
        }

        let message_id =
            chat_protocol::generate_message_id(&local_peer_id, &peer_id, kind, now, &fingerprint);

        let payload = chat_protocol::ChatMessagePayload {
            protocol: chat_protocol::CHAT_PROTOCOL.to_string(),
            message_id: message_id.clone(),
            from_peer_id: local_peer_id,
            to_peer_id: peer_id.clone(),
            kind,
            text: text.clone(),
            media_meta: media_meta.clone(),
            media_bytes: media_bytes.clone(),
            created_at: now,
        };

        let encoded =
            chat_protocol::encode_envelope(&chat_protocol::ChatEnvelope::Message { payload })?;

        let transport_message_id =
            self.queue_encrypted_message_for_peer(peer_id.clone(), encoded)?;

        let chat = storage::ChatMessage {
            message_id,
            peer_id,
            transport_message_id: Some(transport_message_id),
            is_outgoing: true,
            kind: to_kind_string(kind),
            body_text: text,
            media_name: media_meta.as_ref().map(|m| m.file_name.clone()),
            media_mime: media_meta.as_ref().map(|m| m.mime_type.clone()),
            media_width: media_meta.as_ref().and_then(|m| m.width),
            media_height: media_meta.as_ref().and_then(|m| m.height),
            media_duration_ms: media_meta.as_ref().and_then(|m| m.duration_ms),
            media_size: media_bytes.as_ref().map(|b| b.len() as i64),
            media_blob: media_bytes,
            status: "queued".into(),
            created_at: now,
            sent_at: None,
            delivered_at: None,
            read_at: None,
            updated_at: now,
        };
        self.db.upsert_chat_message(&chat)?;
        self.metrics.inc(&self.metrics.chat_messages_queued);
        Ok(to_chat_record(chat))
    }
}

fn now_secs() -> Result<i64, PlexError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| PlexError::Internal { msg: e.to_string() })?
        .as_secs() as i64)
}

fn to_kind_string(kind: chat_protocol::ChatMessageKind) -> String {
    match kind {
        chat_protocol::ChatMessageKind::Text => "text",
        chat_protocol::ChatMessageKind::Photo => "photo",
        chat_protocol::ChatMessageKind::File => "file",
        chat_protocol::ChatMessageKind::VoiceNote => "voice_note",
        chat_protocol::ChatMessageKind::VideoNote => "video_note",
    }
    .to_string()
}

fn parse_kind(kind: &str) -> Result<ChatMessageKindRecord, PlexError> {
    match kind {
        "text" => Ok(ChatMessageKindRecord::Text),
        "photo" => Ok(ChatMessageKindRecord::Photo),
        "file" => Ok(ChatMessageKindRecord::File),
        "voice_note" => Ok(ChatMessageKindRecord::VoiceNote),
        "video_note" => Ok(ChatMessageKindRecord::VideoNote),
        other => Err(PlexError::Internal {
            msg: format!("Unknown chat kind in storage: {other}"),
        }),
    }
}

fn to_chat_record(msg: storage::ChatMessage) -> ChatMessageRecord {
    let kind = parse_kind(&msg.kind).unwrap_or(ChatMessageKindRecord::Text);
    let media_meta = match (msg.media_name, msg.media_mime) {
        (Some(file_name), Some(mime_type)) => Some(ChatMediaMetaRecord {
            file_name,
            mime_type,
            width: msg.media_width,
            height: msg.media_height,
            duration_ms: msg.media_duration_ms,
        }),
        _ => None,
    };

    ChatMessageRecord {
        message_id: msg.message_id,
        peer_id: msg.peer_id,
        transport_message_id: msg.transport_message_id,
        is_outgoing: msg.is_outgoing,
        kind,
        text: msg.body_text,
        media_meta,
        media_bytes: msg.media_blob,
        status: msg.status,
        created_at: msg.created_at,
        sent_at: msg.sent_at,
        delivered_at: msg.delivered_at,
        read_at: msg.read_at,
    }
}

fn to_dialog_record(
    summary: storage::ChatDialogSummary,
) -> Result<ChatDialogSummaryRecord, PlexError> {
    Ok(ChatDialogSummaryRecord {
        peer_id: summary.peer_id,
        last_message_id: summary.last_message_id,
        last_kind: parse_kind(&summary.last_kind)?,
        last_text_preview: summary.last_text_preview,
        last_status: summary.last_status,
        last_created_at: summary.last_created_at,
        unread_count: summary.unread_count,
    })
}
