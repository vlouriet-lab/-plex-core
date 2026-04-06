//! `relay_reputation.rs` — локальная модель репутации relay-узлов.

pub const DEFAULT_REPUTATION: i64 = 50;
pub const MIN_REPUTATION: i64 = 0;
pub const MAX_REPUTATION: i64 = 100;

const SUCCESS_BONUS: i64 = 3;
const FAILURE_PENALTY: i64 = 8;
const DECAY_STEP_SECS: i64 = 6 * 60 * 60; // 6 часов

fn clamp_score(score: i64) -> i64 {
    score.clamp(MIN_REPUTATION, MAX_REPUTATION)
}

/// Плавно возвращает score к нейтральному значению при долгом отсутствии событий.
pub fn apply_decay(score: i64, elapsed_secs: i64) -> i64 {
    if elapsed_secs <= 0 {
        return clamp_score(score);
    }

    let steps = elapsed_secs / DECAY_STEP_SECS;
    if steps <= 0 {
        return clamp_score(score);
    }

    if score > DEFAULT_REPUTATION {
        clamp_score((score - steps).max(DEFAULT_REPUTATION))
    } else if score < DEFAULT_REPUTATION {
        clamp_score((score + steps).min(DEFAULT_REPUTATION))
    } else {
        DEFAULT_REPUTATION
    }
}

/// Обновляет score по результату relay-операции.
pub fn score_after_event(current_score: i64, success: bool) -> i64 {
    if success {
        clamp_score(current_score + SUCCESS_BONUS)
    } else {
        clamp_score(current_score - FAILURE_PENALTY)
    }
}

/// Возвращает uptime в процентах по числу успешных/всех операций.
pub fn uptime_percent(success_count: i64, total_count: i64) -> f64 {
    if total_count <= 0 {
        0.0
    } else {
        ((success_count.max(0) as f64) * 100.0 / (total_count as f64)).clamp(0.0, 100.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decay_moves_score_towards_default() {
        let elapsed = 12 * 60 * 60;
        assert_eq!(apply_decay(70, elapsed), 68);
        assert_eq!(apply_decay(30, elapsed), 32);
    }

    #[test]
    fn score_after_event_applies_bonus_and_penalty() {
        assert_eq!(score_after_event(50, true), 53);
        assert_eq!(score_after_event(50, false), 42);
    }

    #[test]
    fn uptime_percent_is_bounded() {
        assert_eq!(uptime_percent(0, 0), 0.0);
        assert_eq!(uptime_percent(7, 10), 70.0);
    }
}
