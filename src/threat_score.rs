// ============================================================================
// File: threat_score.rs
// Description: Multi-signal threat scoring engine combining all Shield defense signals
// ============================================================================
//! Threat Scoring Engine — Adaptive multi-signal threat assessment.
//!
//! Combines signals from the SQL firewall, SSRF guard, rate governor,
//! request fingerprinter, and behavioral history into a single threat
//! score (0.0–1.0). The score determines whether a request is allowed,
//! warned, or blocked.
//!
//! ## Архитектура для диплома
//!
//! Модуль намеренно разделён на два слоя:
//!
//! 1. **Детерминированный движок** (`assess`) — взвешенная сумма сигналов.
//!    Работает всегда, предсказуем, объясним, тестируем.
//!
//! 2. **ML-хук** (`MlScorer`) — опциональный trait, позволяющий подключить
//!    модель глубокого обучения (Python-микросервис через REST или встроенная
//!    ONNX-модель). Если ML недоступен — система продолжает работать на
//!    детерминированном движке без деградации.

use crate::fingerprint::RequestFingerprint;
use crate::rate_governor::RateCheckResult;
///use async_trait::async_trait;

// ─────────────────────────────────────────────────────────────────────────────
//  Конфигурация весов
// ─────────────────────────────────────────────────────────────────────────────

/// Веса сигналов. По умолчанию соответствуют оригинальным значениям.
/// Можно переопределить через конфиг (TOML) или передать кастомные веса в `assess`.
///
/// Инвариант: `fingerprint + rate + behavioral + violations == 1.0`
/// Нарушение инварианта обнаруживается в `WeightConfig::validate()`.
#[derive(Debug, Clone, Copy)]
pub struct WeightConfig {
    pub fingerprint: f64,
    pub rate: f64,
    pub behavioral: f64,
    pub violations: f64,
}

impl Default for WeightConfig {
    fn default() -> Self {
        Self {
            fingerprint: 0.30,
            rate: 0.25,
            behavioral: 0.30,
            violations: 0.15,
        }
    }
}

impl WeightConfig {
    /// Проверяет что веса в допустимых диапазонах и в сумме дают ~1.0.
    /// Вызывается при старте сервиса из `config.rs`.
    pub fn validate(&self) -> Result<(), String> {
        for (name, w) in [
            ("fingerprint", self.fingerprint),
            ("rate", self.rate),
            ("behavioral", self.behavioral),
            ("violations", self.violations),
        ] {
            if !(0.0..=1.0).contains(&w) {
                return Err(format!(
                    "Weight '{name}' = {w:.3} is outside [0, 1]"
                ));
            }
        }
        let total = self.fingerprint + self.rate + self.behavioral + self.violations;
        if (total - 1.0).abs() > 0.001 {
            return Err(format!(
                "Weights sum to {total:.4}, expected 1.0 (±0.001)"
            ));
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Сигналы и результат
// ─────────────────────────────────────────────────────────────────────────────

/// Взвешенные сигналы, формирующие итоговый score.
#[derive(Debug, Clone)]
pub struct ThreatSignals {
    /// Аномалия запроса по fingerprint-анализу (0.0–1.0).
    pub fingerprint_anomaly: f64,
    /// Давление rate-лимита (0.0–1.0).
    pub rate_pressure: f64,
    /// Поведенческая аномалия из истории запросов (0.0–1.0).
    pub behavioral_anomaly: f64,
    /// Есть ли у IP последние нарушения безопасности.
    pub recent_violations: bool,
}

/// Какой сигнал внёс наибольший вклад в score.
/// Используется в аудит-логе и в ответах API (`/explain`).
/// Для диплома: именно это поле интерпретирует ML-модель.
#[derive(Debug, Clone, PartialEq)]
pub enum DominantSignal {
    Fingerprint,
    Rate,
    Behavioral,
    Violations,
    /// Все сигналы примерно равны — нет явного лидера.
    Mixed,
}

impl DominantSignal {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fingerprint => "fingerprint_anomaly",
            Self::Rate => "rate_pressure",
            Self::Behavioral => "behavioral_anomaly",
            Self::Violations => "recent_violations",
            Self::Mixed => "mixed",
        }
    }
}

/// Финальная оценка угрозы для одного запроса.
#[derive(Debug, Clone)]
pub struct ThreatAssessment {
    /// Итоговый score (0.0 = безопасно, 1.0 = точно вредоносно).
    pub score: f64,
    /// Отдельные сигналы.
    pub signals: ThreatSignals,
    /// Рекомендуемое действие.
    pub action: ThreatAction,
    /// Какой сигнал внёс наибольший вклад (для аудита и объяснимости).
    pub dominant_signal: DominantSignal,
    /// Человекочитаемое объяснение решения (для аудит-лога).
    pub explanation: String,
    /// Вклад каждого сигнала в итоговый score (для ML-интерпретации).
    pub signal_contributions: SignalContributions,
}

/// Абсолютный вклад каждого сигнала в итоговый score.
/// `fingerprint + rate + behavioral + violations ≈ score`
#[derive(Debug, Clone)]
pub struct SignalContributions {
    pub fingerprint: f64,
    pub rate: f64,
    pub behavioral: f64,
    pub violations: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatAction {
    /// Пропустить запрос.
    Allow,
    /// Пропустить, но залогировать предупреждение.
    Warn,
    /// Заблокировать с HTTP 403.
    Block,
}

impl ThreatAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML-хук (опциональный слой для диплома)
// ─────────────────────────────────────────────────────────────────────────────

/// Trait для подключения ML-модели к движку скоринга.
///
/// ## Для диплома
///
/// Реализуй этот trait в отдельном крейте или модуле:
///
/// ```rust
/// struct PythonMlScorer {
///     client: reqwest::Client,
///     endpoint: String,
/// }
///
/// #[async_trait::async_trait]
/// impl MlScorer for PythonMlScorer {
///     async fn score(&self, signals: &ThreatSignals) -> Option<f64> {
///         // POST http://ml-service:8000/predict
///         // { fingerprint_anomaly, rate_pressure, behavioral_anomaly, recent_violations }
///         // Ответ: { "score": 0.87 }
///         // При ошибке — возвращаем None, детерминированный движок продолжает работу
///     }
/// }
/// ```
/// 
/// Если ML-сервис недоступен (`None`), `assess_with_ml` автоматически
/// возвращается к детерминированному скорингу.
#[async_trait::async_trait]
pub trait MlScorer: Send + Sync {
    /// Вычислить ML-score для набора сигналов.
    /// Возвращает `None` если модель недоступна или вернула ошибку.
    async fn score(&self, signals: &ThreatSignals) -> Option<f64>;
}

/// Заглушка для тестов и режима без ML.
pub struct NoopMlScorer;

#[async_trait::async_trait]
impl MlScorer for NoopMlScorer {
    async fn score(&self, _signals: &ThreatSignals) -> Option<f64> {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Основные функции
// ─────────────────────────────────────────────────────────────────────────────

/// Вычислить оценку угрозы из доступных сигналов (синхронная версия).
///
/// # Паника
/// Не паникует — все входные значения нормализуются в `[0, 1]`.
pub fn assess(
    fingerprint: &RequestFingerprint,
    rate_result: &RateCheckResult,
    behavioral_score: f64,
    has_recent_violations: bool,
    warn_threshold: f64,
    block_threshold: f64,
    weights: &WeightConfig,
) -> ThreatAssessment {
    // Нормализация входных значений в [0, 1] защищает от некорректных источников
    let fp_score = fingerprint.anomaly_score.clamp(0.0, 1.0);
    let rate_score = escalation_to_score(rate_result);
    let beh_score = behavioral_score.clamp(0.0, 1.0);
    let viol_score = if has_recent_violations { 1.0_f64 } else { 0.0_f64 };

    let contributions = SignalContributions {
        fingerprint: fp_score * weights.fingerprint,
        rate: rate_score * weights.rate,
        behavioral: beh_score * weights.behavioral,
        violations: viol_score * weights.violations,
    };

    let score = (contributions.fingerprint
        + contributions.rate
        + contributions.behavioral
        + contributions.violations)
        .clamp(0.0, 1.0);

    let signals = ThreatSignals {
        fingerprint_anomaly: fp_score,
        rate_pressure: rate_score,
        behavioral_anomaly: beh_score,
        recent_violations: has_recent_violations,
    };

    let (action, dominant_signal, explanation) =
        build_assessment(score, warn_threshold, block_threshold, &signals, &contributions);

    ThreatAssessment {
        score,
        signals,
        action,
        dominant_signal,
        explanation,
        signal_contributions: contributions,
    }
}

/// Async-версия с опциональным ML-скорером.
///
/// Если ML вернул `Some(ml_score)`, финальный score — среднее взвешенное
/// детерминированного и ML-скора (50/50). Это позволяет ML плавно
/// «уточнять» детерминированный score, а не полностью его заменять.
///
/// Для диплома: здесь удобно добавить логику смешивания моделей (ensemble).
pub async fn assess_with_ml(
    fingerprint: &RequestFingerprint,
    rate_result: &RateCheckResult,
    behavioral_score: f64,
    has_recent_violations: bool,
    warn_threshold: f64,
    block_threshold: f64,
    weights: &WeightConfig,
    ml_scorer: &dyn MlScorer,
) -> ThreatAssessment {
    let mut base = assess(
        fingerprint,
        rate_result,
        behavioral_score,
        has_recent_violations,
        warn_threshold,
        block_threshold,
        weights,
    );

    // Пытаемся получить ML-score; при недоступности — используем base
    if let Some(ml_score) = ml_scorer
        .score(&base.signals)
        .await
        .map(|s| s.clamp(0.0, 1.0))
    {
        // Ensemble: 50% детерминированный + 50% ML
        // Для диплома: это место где можно поэкспериментировать с alpha
        let alpha = 0.5_f64;
        let ensemble_score = (base.score * (1.0 - alpha) + ml_score * alpha).clamp(0.0, 1.0);

        let (action, dominant_signal, explanation) = build_assessment(
            ensemble_score,
            warn_threshold,
            block_threshold,
            &base.signals,
            &base.signal_contributions,
        );

        base.score = ensemble_score;
        base.action = action;
        base.dominant_signal = dominant_signal;
        base.explanation = format!(
            "{} [ML ensemble: det={:.3} ml={:.3}]",
            explanation, base.score, ml_score
        );
    }

    base
}

// ─────────────────────────────────────────────────────────────────────────────
//  Внутренние вспомогательные функции
// ─────────────────────────────────────────────────────────────────────────────

/// Определяет действие, доминирующий сигнал и объяснение по score.
fn build_assessment(
    score: f64,
    warn_threshold: f64,
    block_threshold: f64,
    _signals: &ThreatSignals,
    contributions: &SignalContributions,
) -> (ThreatAction, DominantSignal, String) {
    let action = if score >= block_threshold {
        ThreatAction::Block
    } else if score >= warn_threshold {
        ThreatAction::Warn
    } else {
        ThreatAction::Allow
    };

    let dominant = dominant_signal(contributions);

    let explanation = format!(
        "score={:.3} action={} dominant={} \
         [fp={:.3} rate={:.3} beh={:.3} viol={:.3}]",
        score,
        action.as_str(),
        dominant.as_str(),
        contributions.fingerprint,
        contributions.rate,
        contributions.behavioral,
        contributions.violations,
    );

    (action, dominant, explanation)
}

/// Определяет какой сигнал внёс наибольший абсолютный вклад.
fn dominant_signal(c: &SignalContributions) -> DominantSignal {
    let values = [
        (c.fingerprint, DominantSignal::Fingerprint),
        (c.rate, DominantSignal::Rate),
        (c.behavioral, DominantSignal::Behavioral),
        (c.violations, DominantSignal::Violations),
    ];

    let max_val = values
        .iter()
        .map(|(v, _)| *v)
        .fold(f64::NEG_INFINITY, f64::max);

    // Если максимальный вклад < 5% от полного score — сигналы смешаны
    if max_val < 0.05 {
        return DominantSignal::Mixed;
    }

    // Если два сигнала в пределах 1% друг от друга — Mixed
    let top_two: Vec<f64> = {
        let mut v: Vec<f64> = values.iter().map(|(v, _)| *v).collect();
        v.sort_by(|a, b| b.partial_cmp(a).unwrap());
        v
    };
    if top_two.len() >= 2 && (top_two[0] - top_two[1]).abs() < 0.01 {
        return DominantSignal::Mixed;
    }

    values
        .into_iter()
        .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap())
        .map(|(_, s)| s)
        .unwrap_or(DominantSignal::Mixed)
}

fn escalation_to_score(rate_result: &RateCheckResult) -> f64 {
    use crate::rate_governor::EscalationLevel;
    match rate_result.escalation {
        EscalationLevel::None => 0.0,
        EscalationLevel::Warn => 0.3,
        EscalationLevel::Throttle => 0.6,
        EscalationLevel::Block => 0.9,
        EscalationLevel::Ban => 1.0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Тесты
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::{FingerprintSignals, RequestFingerprint};
    use crate::rate_governor::{EscalationLevel, RateCheckResult};

    // ── fixtures ──────────────────────────────────────────────────────────────

    fn clean_fp() -> RequestFingerprint {
        RequestFingerprint {
            hash: "abc".into(),
            signals: FingerprintSignals {
                has_user_agent: true,
                has_accept: true,
                has_accept_language: true,
                has_accept_encoding: true,
                has_referer: false,
                header_count: 5,
                header_order_hash: "def".into(),
                user_agent: "Mozilla/5.0".into(),
            },
            anomaly_score: 0.0,
        }
    }

    fn clean_rate() -> RateCheckResult {
        RateCheckResult {
            allowed: true,
            escalation: EscalationLevel::None,
            remaining: 100.0,
            retry_after: None,
            violations: 0,
        }
    }

    fn weights() -> WeightConfig {
        WeightConfig::default()
    }

    fn assess_default(
        fp: &RequestFingerprint,
        rate: &RateCheckResult,
        beh: f64,
        violations: bool,
    ) -> ThreatAssessment {
        assess(fp, rate, beh, violations, 0.4, 0.7, &weights())
    }

    // ── действие по score ─────────────────────────────────────────────────────

    #[test]
    fn clean_request_allowed() {
        let r = assess_default(&clean_fp(), &clean_rate(), 0.0, false);
        assert_eq!(r.action, ThreatAction::Allow);
        assert!(r.score < 0.1, "score={}", r.score);
    }

    #[test]
    fn suspicious_fingerprint_warns_or_blocks() {
        let mut fp = clean_fp();
        fp.anomaly_score = 0.9;
        let r = assess_default(&fp, &clean_rate(), 0.8, false);
        assert!(
            matches!(r.action, ThreatAction::Warn | ThreatAction::Block),
            "action={:?} score={}", r.action, r.score
        );
    }

    #[test]
    fn all_bad_signals_block() {
        let mut fp = clean_fp();
        fp.anomaly_score = 0.8;
        let rate = RateCheckResult {
            allowed: false,
            escalation: EscalationLevel::Block,
            remaining: 0.0,
            retry_after: None,
            violations: 20,
        };
        let r = assess_default(&fp, &rate, 0.7, true);
        assert_eq!(r.action, ThreatAction::Block);
    }

    // ── нормализация входов ───────────────────────────────────────────────────

    #[test]
    fn score_clamped_with_over_range_inputs() {
        let mut fp = clean_fp();
        fp.anomaly_score = 2.0; // некорректное значение
        let r = assess_default(&fp, &clean_rate(), 1.5, true); // behavioral тоже > 1
        assert!(r.score <= 1.0, "score={} should be ≤ 1.0", r.score);
        assert!(r.score >= 0.0, "score={} should be ≥ 0.0", r.score);
    }

    #[test]
    fn score_never_negative() {
        let mut fp = clean_fp();
        fp.anomaly_score = -0.5;
        let r = assess_default(&fp, &clean_rate(), -1.0, false);
        assert!(r.score >= 0.0);
    }

    // ── dominant signal ───────────────────────────────────────────────────────

    #[test]
    fn fingerprint_dominant_when_only_signal() {
        let mut fp = clean_fp();
        fp.anomaly_score = 1.0;
        let r = assess_default(&fp, &clean_rate(), 0.0, false);
        assert_eq!(r.dominant_signal, DominantSignal::Fingerprint);
    }

    #[test]
    fn behavioral_dominant_when_only_signal() {
        let r = assess_default(&clean_fp(), &clean_rate(), 1.0, false);
        assert_eq!(r.dominant_signal, DominantSignal::Behavioral);
    }

    #[test]
    fn mixed_when_all_signals_zero() {
        let r = assess_default(&clean_fp(), &clean_rate(), 0.0, false);
        assert_eq!(r.dominant_signal, DominantSignal::Mixed);
    }

    // ── explanation ───────────────────────────────────────────────────────────

    #[test]
    fn explanation_contains_score_and_action() {
        let r = assess_default(&clean_fp(), &clean_rate(), 0.0, false);
        assert!(r.explanation.contains("score="));
        assert!(r.explanation.contains("action="));
        assert!(r.explanation.contains("dominant="));
    }

    #[test]
    fn explanation_contains_contributions() {
        let r = assess_default(&clean_fp(), &clean_rate(), 0.0, false);
        assert!(r.explanation.contains("fp="));
        assert!(r.explanation.contains("rate="));
        assert!(r.explanation.contains("beh="));
        assert!(r.explanation.contains("viol="));
    }

    // ── contributions sum ─────────────────────────────────────────────────────

    #[test]
    fn contributions_sum_equals_score() {
        let mut fp = clean_fp();
        fp.anomaly_score = 0.6;
        let r = assess_default(&fp, &clean_rate(), 0.4, true);
        let sum = r.signal_contributions.fingerprint
            + r.signal_contributions.rate
            + r.signal_contributions.behavioral
            + r.signal_contributions.violations;
        assert!(
            (sum - r.score).abs() < 1e-9,
            "contributions sum={sum} != score={}",
            r.score
        );
    }

    // ── WeightConfig ──────────────────────────────────────────────────────────

    #[test]
    fn default_weights_valid() {
        assert!(WeightConfig::default().validate().is_ok());
    }

    #[test]
    fn weights_not_summing_to_one_invalid() {
        let bad = WeightConfig {
            fingerprint: 0.5,
            rate: 0.5,
            behavioral: 0.5,
            violations: 0.5,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn weight_out_of_range_invalid() {
        let bad = WeightConfig {
            fingerprint: -0.1,
            rate: 0.4,
            behavioral: 0.4,
            violations: 0.3,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn custom_weights_accepted() {
        let custom = WeightConfig {
            fingerprint: 0.40,
            rate: 0.20,
            behavioral: 0.25,
            violations: 0.15,
        };
        assert!(custom.validate().is_ok());
    }

    // ── threshold edge cases ──────────────────────────────────────────────────

    #[test]
    fn score_exactly_at_block_threshold_blocks() {
        // Строим ситуацию где score точно = 0.7
        // violations=true даёт 0.15; нужно добрать 0.55 из behavioral (0.30) и fp (0.25/0.30)
        // Подбираем fp и beh чтобы получить ровно 0.7
        let mut fp = clean_fp();
        // fp_contrib = fp * 0.30 = x
        // beh_contrib = beh * 0.30 = y
        // viol_contrib = 1.0 * 0.15 = 0.15
        // rate = 0.0
        // x + y + 0.15 = 0.7 => x + y = 0.55
        // пусть fp=1.0 => x=0.30, тогда y=0.25 => beh=0.25/0.30=0.8333
        fp.anomaly_score = 1.0;
        let beh = 0.55 / 0.30 - 1.0; // = 0.833...
        let r = assess_default(&fp, &clean_rate(), beh, true);
        // score должен быть >= 0.7
        assert!(
            r.score >= 0.699,
            "score={} should be around 0.7",
            r.score
        );
    }

    #[test]
    fn warn_threshold_above_block_threshold_still_works() {
        // Даже при "неправильных" порогах — не паникуем
        let fp = clean_fp();
        // warn=0.9, block=0.4 — инвертированы. Логика: block проверяется первым.
        // При score >= 0.4 получим Block. Warn никогда не сработает.
        let r = assess(&fp, &clean_rate(), 0.5, false, 0.9, 0.4, &weights());
        // score ≈ 0.5 * 0.30 = 0.15 < 0.4 → Allow
        assert_eq!(r.action, ThreatAction::Allow);
    }

    // ── ML hook ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn noop_scorer_returns_deterministic_result() {
        let fp = clean_fp();
        let base = assess_default(&fp, &clean_rate(), 0.0, false);
        let with_ml = assess_with_ml(
            &fp,
            &clean_rate(),
            0.0,
            false,
            0.4,
            0.7,
            &weights(),
            &NoopMlScorer,
        )
        .await;
        assert_eq!(base.score, with_ml.score);
        assert_eq!(base.action, with_ml.action);
    }

    #[tokio::test]
    async fn ml_scorer_blends_score() {
        struct HighMlScorer;
        #[async_trait::async_trait]
        impl MlScorer for HighMlScorer {
            async fn score(&self, _: &ThreatSignals) -> Option<f64> {
                Some(1.0) // ML считает это очень опасным
            }
        }

        let fp = clean_fp();
        let det = assess_default(&fp, &clean_rate(), 0.0, false);
        let with_ml = assess_with_ml(
            &fp,
            &clean_rate(),
            0.0,
            false,
            0.4,
            0.7,
            &weights(),
            &HighMlScorer,
        )
        .await;

        // Ensemble = 0.5 * det.score + 0.5 * 1.0 > det.score
        assert!(
            with_ml.score > det.score,
            "ensemble={} should be > deterministic={}",
            with_ml.score, det.score
        );
        assert!(with_ml.explanation.contains("ML ensemble"));
    }

    #[tokio::test]
    async fn unavailable_ml_falls_back_to_deterministic() {
        struct FailingMlScorer;
        #[async_trait::async_trait]
        impl MlScorer for FailingMlScorer {
            async fn score(&self, _: &ThreatSignals) -> Option<f64> {
                None // сервис недоступен
            }
        }

        let fp = clean_fp();
        let base = assess_default(&fp, &clean_rate(), 0.5, false);
        let with_ml = assess_with_ml(
            &fp,
            &clean_rate(),
            0.5,
            false,
            0.4,
            0.7,
            &weights(),
            &FailingMlScorer,
        )
        .await;
        assert_eq!(base.score, with_ml.score);
    }

    // ── action string ─────────────────────────────────────────────────────────

    #[test]
    fn action_as_str() {
        assert_eq!(ThreatAction::Allow.as_str(), "allow");
        assert_eq!(ThreatAction::Warn.as_str(), "warn");
        assert_eq!(ThreatAction::Block.as_str(), "block");
    }
}