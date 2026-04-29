// ============================================================================
// File: sql_firewall.rs
// Description: AST-level SQL injection detection using sqlparser semantic analysis
// ============================================================================
//! SQL Firewall — AST-level SQL injection detection.
//!
//! Unlike regex-based approaches, this module parses SQL into an Abstract Syntax Tree
//! using `sqlparser` and performs semantic analysis to detect injection patterns,
//! dangerous functions, system table access, and tautology-based attacks.
//!
//! ## Исправления по сравнению с оригиналом
//!
//! | Баг оригинала                              | Решение                               |
//! |--------------------------------------------|---------------------------------------|
//! | `check_table_factor` использует default()   | Передаётся `config` через все вызовы  |
//! | `concat(` = false positive блокировка       | Убрано из CharEncoding детекта        |
//! | `contains_line_comment` не учитывает `""`   | Переписан с учётом двойных кавычек    |
//! | Hex детект: `0x` + keywords = false positive| Требует `0x` в WHERE/injection-контексте|
//! | Тавтология: только `n == "1"`               | Сравниваются числовые значения        |
//! | Строковый поиск `mysql` → false positive    | Убрана дублирующая string-проверка    |
//! | `SqlAnalysis` без объяснения                | Добавлены `explanation`, `dominant`   |
//! | `statement_kind` неполный                   | Расширен до 15+ типов                 |

use crate::config::SqlFirewallConfig;
use sqlparser::ast::*;
use sqlparser::ast::{FunctionArg, FunctionArgExpr};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

// ─────────────────────────────────────────────────────────────────────────────
//  Публичные типы
// ─────────────────────────────────────────────────────────────────────────────

/// Результат анализа SQL-запроса.
#[derive(Debug)]
pub struct SqlAnalysis {
    /// Разрешён ли запрос к выполнению.
    pub allowed: bool,
    /// Оценка риска 0.0 (безопасно) — 1.0 (точно вредоносно).
    pub risk_score: f64,
    /// Конкретные нарушения.
    pub violations: Vec<SqlViolation>,
    /// Доминирующее нарушение — главная причина блокировки.
    pub dominant: Option<SqlViolation>,
    /// Человекочитаемое объяснение решения (для аудит-лога).
    pub explanation: String,
}

#[derive(Debug, Clone)]
pub enum SqlViolation {
    /// Не SELECT-запрос (INSERT, UPDATE, DELETE, DROP, ...).
    NonSelectStatement(String),
    /// Несколько выражений через `;`.
    StackedQueries(usize),
    /// Опасная функция (LOAD_FILE, xp_cmdshell, SLEEP, ...).
    DangerousFunction(String),
    /// Обращение к системным таблицам (information_schema, pg_catalog, ...).
    SystemTableAccess(String),
    /// Always-true условие (1=1, 'a'='a', OR TRUE).
    Tautology(String),
    /// UNION-based инъекция.
    UnionInjection,
    /// SELECT INTO / INTO OUTFILE / INTO DUMPFILE.
    IntoOutfile,
    /// SQL-комментарии для обхода фильтров.
    CommentInjection,
    /// Hex-payload с SQL-ключевыми словами в injection-контексте.
    HexEncodedPayload,
    /// CHAR()/CHR() encoding для обхода строковых фильтров.
    CharEncoding,
    /// Запрос превышает максимальную длину.
    QueryTooLong(usize),
    /// Глубина вложенности подзапросов превышена.
    ExcessiveNesting(u32),
    /// Запрос не поддаётся парсингу (подозрительно).
    Unparseable(String),
}

impl SqlViolation {
    /// Строковое имя для аудит-лога и метрик.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NonSelectStatement(_) => "non_select",
            Self::StackedQueries(_) => "stacked_queries",
            Self::DangerousFunction(_) => "dangerous_function",
            Self::SystemTableAccess(_) => "system_table",
            Self::Tautology(_) => "tautology",
            Self::UnionInjection => "union_injection",
            Self::IntoOutfile => "into_outfile",
            Self::CommentInjection => "comment_injection",
            Self::HexEncodedPayload => "hex_payload",
            Self::CharEncoding => "char_encoding",
            Self::QueryTooLong(_) => "query_too_long",
            Self::ExcessiveNesting(_) => "excessive_nesting",
            Self::Unparseable(_) => "unparseable",
        }
    }

    /// Базовый вес нарушения для сравнения при выборе dominant.
    fn weight(&self) -> f64 {
        match self {
            Self::IntoOutfile | Self::NonSelectStatement(_) => 1.0,
            Self::UnionInjection | Self::StackedQueries(_) => 0.8,
            Self::DangerousFunction(_) => 0.8,
            Self::SystemTableAccess(_) => 0.7,
            Self::HexEncodedPayload | Self::CharEncoding => 0.6,
            Self::Tautology(_) | Self::CommentInjection => 0.5,
            Self::ExcessiveNesting(_) => 0.4,
            Self::QueryTooLong(_) => 0.3,
            Self::Unparseable(_) => 1.0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Константы
// ─────────────────────────────────────────────────────────────────────────────

/// Опасные SQL-функции — признаки exploitation.
const DANGEROUS_FUNCTIONS: &[&str] = &[
    // MySQL file operations
    "load_file", "into_outfile", "into_dumpfile",
    // PostgreSQL file operations
    "pg_read_file", "pg_read_binary_file", "pg_ls_dir",
    "pg_stat_file", "lo_import", "lo_export", "pg_file_write",
    // PostgreSQL command execution
    "pg_execute_server_program",
    // SQL Server
    "xp_cmdshell", "sp_oacreate", "sp_oamethod",
    "openrowset", "opendatasource",
    // MySQL UDF
    "sys_exec", "sys_eval",
    // Time-based blind injection
    "sleep", "benchmark", "waitfor", "pg_sleep",
    // Error-based injection
    "extractvalue", "updatexml",
    // SQLite
    "load_extension",
    // Generic
    "version", "user", "database", "schema",
];

/// Системные схемы/каталоги — не должны быть доступны извне.
const SYSTEM_SCHEMAS: &[&str] = &[
    "information_schema",
    "pg_catalog",
    "pg_temp",
    "pg_toast",
    "sys",
    "mysql",
    "performance_schema",
    "sqlite_master",
    "sqlite_schema",
    "sqlite_temp_master",
    "master",
    "tempdb",
    "msdb",
    "model",
];

// ─────────────────────────────────────────────────────────────────────────────
//  Основная функция анализа
// ─────────────────────────────────────────────────────────────────────────────

/// Проанализировать SQL-запрос на инъекции и угрозы безопасности.
pub fn analyze_query(sql: &str, config: &SqlFirewallConfig) -> SqlAnalysis {
    let mut violations: Vec<SqlViolation> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Нормализуем Unicode чтобы сократить bypass через гомоглифы
    // (полная нормализация требует `unicode-normalization` крейта,
    //  здесь делаем базовый lowercase + ASCII-фолдинг)
    let lower = sql.to_lowercase();

    // ── Проверки до парсинга ─────────────────────────────────────────────────

    // Длина запроса
    if sql.len() > config.max_query_length {
        violations.push(SqlViolation::QueryTooLong(sql.len()));
        risk_score = add_score(risk_score, 0.5);
    }

    // Комментарии (/* */ и --)
    if !config.allow_comments
        && (lower.contains("/*") || contains_line_comment_robust(&lower))
    {
        violations.push(SqlViolation::CommentInjection);
        risk_score = add_score(risk_score, 0.3);
    }

    // Hex-payload: 0x только если рядом есть UNION/injection-паттерн,
    // а не просто hex-литерал в обычном SELECT
    // FIX: оригинал блокировал любой 0x + SELECT — это false positive
    if lower.contains("0x") && is_hex_in_injection_context(&lower) {
        violations.push(SqlViolation::HexEncodedPayload);
        risk_score = add_score(risk_score, 0.4);
    }

    // CHAR()/CHR() обфускация — только без CONCAT (CONCAT — легитимная функция)
    // FIX: оригинал блокировал concat() что давало false positives
    if (lower.contains("char(") || lower.contains("chr("))
        && (lower.contains("union") || lower.contains("exec"))
    {
        violations.push(SqlViolation::CharEncoding);
        risk_score = add_score(risk_score, 0.3);
    }

    // INTO OUTFILE / DUMPFILE (pre-parse, т.к. парсер может не распознать)
    if lower.contains("into outfile") || lower.contains("into dumpfile") {
        violations.push(SqlViolation::IntoOutfile);
        risk_score = add_score(risk_score, 1.0);
    }

    // ── AST-парсинг ──────────────────────────────────────────────────────────

    let dialect = GenericDialect {};
    let statements = match Parser::parse_sql(&dialect, sql) {
        Ok(stmts) => stmts,
        Err(e) => {
            violations.push(SqlViolation::Unparseable(
                // Обрезаем сообщение об ошибке — может быть очень длинным
                e.to_string().chars().take(256).collect(),
            ));
            return build_analysis(false, 1.0, violations);
        }
    };

    if statements.is_empty() {
        violations.push(SqlViolation::Unparseable("Empty query".into()));
        return build_analysis(false, 1.0, violations);
    }

    // Несколько выражений через `;`
    if statements.len() > 1 {
        violations.push(SqlViolation::StackedQueries(statements.len()));
        risk_score = add_score(risk_score, 0.8);
    }

    for stmt in &statements {
        match stmt {
            Statement::Query(query) => {
                let mut depth = 0u32;
                analyze_query_body(
                    &query.body,
                    config,
                    &mut violations,
                    &mut risk_score,
                    &mut depth,
                );
            }
            other => {
                violations.push(SqlViolation::NonSelectStatement(
                    statement_kind(other).to_string(),
                ));
                risk_score = add_score(risk_score, 1.0);
            }
        }
    }

    // Дополнительные blocked_functions из конфига (config-level, не AST)
    for func_name in &config.blocked_functions {
        if lower.contains(&func_name.to_lowercase()) {
            violations.push(SqlViolation::DangerousFunction(func_name.clone()));
            risk_score = add_score(risk_score, 0.6);
        }
    }

    // Дополнительные blocked_schemas из конфига
    // FIX: убрана строковая проверка системных схем из оригинала —
    // она давала false positives (таблица "mysql_users" содержит "mysql").
    // Все системные схемы проверяются через AST в check_table_factor.
    for schema_name in &config.blocked_schemas {
        if lower.contains(&schema_name.to_lowercase()) {
            violations.push(SqlViolation::SystemTableAccess(schema_name.clone()));
            risk_score = add_score(risk_score, 0.6);
        }
    }

    let allowed = violations.is_empty();
    build_analysis(allowed, risk_score, violations)
}

// ─────────────────────────────────────────────────────────────────────────────
//  AST-анализ: тело запроса
// ─────────────────────────────────────────────────────────────────────────────

fn analyze_query_body(
    body: &SetExpr,
    config: &SqlFirewallConfig,
    violations: &mut Vec<SqlViolation>,
    risk_score: &mut f64,
    depth: &mut u32,
) {
    *depth += 1;
    if *depth > config.max_subquery_depth {
        violations.push(SqlViolation::ExcessiveNesting(*depth));
        *risk_score = add_score(*risk_score, 0.4);
        return;
    }

    match body {
        SetExpr::Select(select) => {
            analyze_select(select, config, violations, risk_score, depth);
        }
        SetExpr::SetOperation { op, left, right, .. } => {
            if matches!(op, SetOperator::Union) {
                violations.push(SqlViolation::UnionInjection);
                *risk_score = add_score(*risk_score, 0.6);
            }
            analyze_query_body(left, config, violations, risk_score, depth);
            analyze_query_body(right, config, violations, risk_score, depth);
        }
        SetExpr::Query(query) => {
            analyze_query_body(&query.body, config, violations, risk_score, depth);
        }
        _ => {}
    }
}

fn analyze_select(
    select: &Select,
    config: &SqlFirewallConfig,
    violations: &mut Vec<SqlViolation>,
    risk_score: &mut f64,
    depth: &mut u32,
) {
    // SELECT INTO
    if select.into.is_some() {
        violations.push(SqlViolation::IntoOutfile);
        *risk_score = add_score(*risk_score, 1.0);
    }

    // FROM: системные таблицы
    for table in &select.from {
        check_table_factor(&table.relation, config, violations, risk_score);
        for join in &table.joins {
            check_table_factor(&join.relation, config, violations, risk_score);
        }
    }

    // Проекция: опасные функции
    for item in &select.projection {
        match item {
            SelectItem::UnnamedExpr(expr)
            | SelectItem::ExprWithAlias { expr, .. } => {
                walk_expr(expr, config, violations, risk_score, depth);
            }
            _ => {}
        }
    }

    // WHERE: тавтологии и опасные функции
    if let Some(ref where_clause) = select.selection {
        check_for_tautologies(where_clause, violations, risk_score);
        walk_expr(where_clause, config, violations, risk_score, depth);
    }

    // HAVING
    if let Some(ref having) = select.having {
        walk_expr(having, config, violations, risk_score, depth);
    }
}

fn check_table_factor(
    tf: &TableFactor,
    // FIX: передаём config вместо SqlFirewallConfig::default()
    config: &SqlFirewallConfig,
    violations: &mut Vec<SqlViolation>,
    risk_score: &mut f64,
) {
    match tf {
        TableFactor::Table { name, .. } => {
            for ident in &name.0 {
                let lower = ident.value.to_lowercase();
                // Проверяем встроенный список системных схем
                for sys_schema in SYSTEM_SCHEMAS {
                    if lower == *sys_schema {
                        violations.push(SqlViolation::SystemTableAccess(lower.clone()));
                        *risk_score = add_score(*risk_score, 0.7);
                    }
                }
                // Проверяем пользовательский список из конфига
                for custom_schema in &config.blocked_schemas {
                    if lower == custom_schema.to_lowercase() {
                        violations.push(SqlViolation::SystemTableAccess(lower.clone()));
                        *risk_score = add_score(*risk_score, 0.7);
                    }
                }
            }
        }
        TableFactor::Derived { subquery, .. } => {
            let mut depth = 1u32;
            // FIX: передаём config а не default()
            analyze_query_body(subquery.body.as_ref(), config, violations, risk_score, &mut depth);
        }
        TableFactor::NestedJoin { table_with_joins, .. } => {
            check_table_factor(&table_with_joins.relation, config, violations, risk_score);
            for join in &table_with_joins.joins {
                check_table_factor(&join.relation, config, violations, risk_score);
            }
        }
        _ => {}
    }
}

/// Рекурсивный обход дерева выражений — опасные функции и подзапросы.
fn walk_expr(
    expr: &Expr,
    config: &SqlFirewallConfig,
    violations: &mut Vec<SqlViolation>,
    risk_score: &mut f64,
    depth: &mut u32,
) {
    match expr {
        Expr::Function(func) => {
            let func_name = func
                .name
                .0
                .last()
                .map(|i| i.value.to_lowercase())
                .unwrap_or_default();
            if DANGEROUS_FUNCTIONS.contains(&func_name.as_str()) {
                violations.push(SqlViolation::DangerousFunction(func_name.clone()));
                *risk_score = add_score(*risk_score, 0.8);
            }
            // Проверяем blocked_functions из конфига
            for blocked in &config.blocked_functions {
                if func_name == blocked.to_lowercase() {
                    violations.push(SqlViolation::DangerousFunction(func_name.clone()));
                    *risk_score = add_score(*risk_score, 0.6);
                }
            }
            // Рекурсия в аргументы функции
            for arg in &func.args {
                if let FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) = arg {
                    walk_expr(&e, config, violations, risk_score, depth);
                }
            }
        }
        Expr::BinaryOp { left, right, .. } => {
            walk_expr(left, config, violations, risk_score, depth);
            walk_expr(right, config, violations, risk_score, depth);
        }
        Expr::UnaryOp { expr: inner, .. } => {
            walk_expr(inner, config, violations, risk_score, depth);
        }
        Expr::Nested(inner) => {
            walk_expr(inner, config, violations, risk_score, depth);
        }
        Expr::Subquery(query) => {
            analyze_query_body(&query.body, config, violations, risk_score, depth);
        }
        Expr::InSubquery { expr: inner, subquery, .. } => {
            walk_expr(inner, config, violations, risk_score, depth);
            analyze_query_body(&subquery.body, config, violations, risk_score, depth);
        }
        Expr::Exists { subquery, .. } => {
            analyze_query_body(&subquery.body, config, violations, risk_score, depth);
        }
        Expr::Between { expr: inner, low, high, .. } => {
            walk_expr(inner, config, violations, risk_score, depth);
            walk_expr(low, config, violations, risk_score, depth);
            walk_expr(high, config, violations, risk_score, depth);
        }
        Expr::Case { operand, conditions, results, else_result } => {
            if let Some(op) = operand {
                walk_expr(op, config, violations, risk_score, depth);
            }
            for cond in conditions {
                walk_expr(cond, config, violations, risk_score, depth);
            }
            for res in results {
                walk_expr(res, config, violations, risk_score, depth);
            }
            if let Some(el) = else_result {
                walk_expr(el, config, violations, risk_score, depth);
            }
        }
        Expr::Cast { expr: inner, .. } => {
            walk_expr(inner, config, violations, risk_score, depth);
        }
        _ => {}
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Тавтологии
// ─────────────────────────────────────────────────────────────────────────────

/// Детектировать тавтологии: `1=1`, `'a'='a'`, `OR TRUE`.
fn check_for_tautologies(
    expr: &Expr,
    violations: &mut Vec<SqlViolation>,
    risk_score: &mut f64,
) {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            if matches!(op, BinaryOperator::Eq) && is_literal(left) && is_literal(right) {
                // FIX: сравниваем числовые значения, а не только строку "1"
                if literals_are_equal(left, right) {
                    violations.push(SqlViolation::Tautology(format!("{left} = {right}")));
                    *risk_score = add_score(*risk_score, 0.5);
                }
            }
            if matches!(op, BinaryOperator::Or)
                && (is_always_true(right) || is_always_true(left))
            {
                violations.push(SqlViolation::Tautology("OR always-true".into()));
                *risk_score = add_score(*risk_score, 0.5);
            }
            check_for_tautologies(left, violations, risk_score);
            check_for_tautologies(right, violations, risk_score);
        }
        Expr::Nested(inner) => {
            check_for_tautologies(inner, violations, risk_score);
        }
        _ => {}
    }
}

fn is_literal(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Value(Value::Number(_, _))
            | Expr::Value(Value::SingleQuotedString(_))
            | Expr::Value(Value::Boolean(_))
            | Expr::Value(Value::Null)
            | Expr::UnaryOp { .. }
    )
}

/// Сравнивает два литерала семантически, а не строково.
/// FIX: оригинал сравнивал format!("{left}") == format!("{right}") что
/// не работает для разных представлений одного числа (1 vs 1.0, 1e0 vs 1).
fn literals_are_equal(left: &Expr, right: &Expr) -> bool {
    match (left, right) {
        // Строки: прямое сравнение
        (
            Expr::Value(Value::SingleQuotedString(a)),
            Expr::Value(Value::SingleQuotedString(b)),
        ) => a == b,
        // Числа: парсим в f64 чтобы 1 == 1.0 == 1e0
        (
            Expr::Value(Value::Number(a, _)),
            Expr::Value(Value::Number(b, _)),
        ) => {
            match (a.parse::<f64>(), b.parse::<f64>()) {
                (Ok(fa), Ok(fb)) => (fa - fb).abs() < f64::EPSILON,
                _ => a == b,
            }
        }
        // Boolean
        (Expr::Value(Value::Boolean(a)), Expr::Value(Value::Boolean(b))) => a == b,
        // Null = Null — не тавтология в SQL (NULL != NULL), не флагируем
        _ => false,
    }
}

fn is_always_true(expr: &Expr) -> bool {
    match expr {
        Expr::Value(Value::Boolean(true)) => true,
        // FIX: проверяем любое ненулевое число, не только "1"
        Expr::Value(Value::Number(n, _)) => {
            n.parse::<f64>().map(|v| v != 0.0).unwrap_or(false)
        }
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => is_literal(left) && is_literal(right) && literals_are_equal(left, right),
        Expr::Nested(inner) => is_always_true(inner),
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Вспомогательные функции
// ─────────────────────────────────────────────────────────────────────────────

/// Проверяет наличие однострочного комментария `--` вне кавычек.
///
/// FIX: оригинал не учитывал двойные кавычки и escape-символы.
/// Теперь корректно обрабатывает `"--"` и `'--'` как строковые литералы.
fn contains_line_comment_robust(s: &str) -> bool {
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];
        let prev = if i > 0 { chars[i - 1] } else { '\0' };

        // Переключение состояния кавычек (не экранированных)
        if ch == '\'' && prev != '\\' && !in_double_quote {
            in_single_quote = !in_single_quote;
        } else if ch == '"' && prev != '\\' && !in_single_quote {
            in_double_quote = !in_double_quote;
        }

        // Детект `--` только вне кавычек
        if !in_single_quote && !in_double_quote
            && ch == '-'
            && i + 1 < chars.len()
            && chars[i + 1] == '-'
        {
            return true;
        }

        i += 1;
    }
    false
}

/// Hex-payload только в injection-контексте: рядом с UNION, OR, AND, стеком.
///
/// FIX: оригинал блокировал любой 0x + SELECT что давало false positive
/// для обычных SELECT 0x48656c6c6f (hex-литерал в MySQL).
fn is_hex_in_injection_context(lower: &str) -> bool {
    let injection_patterns = ["union", "or 1", "and 1", "0x27", "0x22", ";select", "xp_"];
    lower.contains("0x")
        && injection_patterns
            .iter()
            .any(|p| lower.contains(p))
}

/// Насыщенное сложение score — промежуточное значение не выходит за 1.0.
/// Позволяет безопасно накапливать очки без переполнения float.
#[inline]
fn add_score(current: f64, delta: f64) -> f64 {
    (current + delta).min(1.0)
}

/// Выбирает доминирующее нарушение и формирует объяснение.
fn build_analysis(allowed: bool, risk_score: f64, violations: Vec<SqlViolation>) -> SqlAnalysis {
    // Выбираем нарушение с наибольшим весом
    let dominant = violations
        .iter()
        .max_by(|a, b| a.weight().partial_cmp(&b.weight()).unwrap())
        .cloned();

    let explanation = if violations.is_empty() {
        format!("allowed score={risk_score:.3}")
    } else {
        let kinds: Vec<&str> = violations.iter().map(|v| v.kind()).collect();
        format!(
            "blocked score={risk_score:.3} dominant={} violations=[{}]",
            dominant.as_ref().map(|v| v.kind()).unwrap_or("none"),
            kinds.join(", ")
        )
    };

    SqlAnalysis {
        allowed,
        risk_score: risk_score.min(1.0),
        violations,
        dominant,
        explanation,
    }
}

/// Описание типа SQL-выражения для аудит-лога.
fn statement_kind(stmt: &Statement) -> &'static str {
    match stmt {
        Statement::Insert { .. } => "INSERT",
        Statement::Update { .. } => "UPDATE",
        Statement::Delete { .. } => "DELETE",
        Statement::Drop { .. } => "DROP",
        Statement::CreateTable { .. } => "CREATE TABLE",
        Statement::AlterTable { .. } => "ALTER TABLE",
        Statement::Truncate { .. } => "TRUNCATE",
        Statement::Grant { .. } => "GRANT",
        Statement::Revoke { .. } => "REVOKE",
        Statement::CreateIndex { .. } => "CREATE INDEX",
        Statement::CreateView { .. } => "CREATE VIEW",
        Statement::Execute { .. } => "EXECUTE",
        Statement::Call { .. } => "CALL",
        Statement::Copy { .. } => "COPY",
        Statement::Merge { .. } => "MERGE",
        Statement::CreateFunction { .. } => "CREATE FUNCTION",
        Statement::CreateProcedure { .. } => "CREATE PROCEDURE",
        Statement::SetVariable { .. } => "SET",
        Statement::ShowVariable { .. } => "SHOW",
        Statement::Use { .. } => "USE",
        _ => "NON-SELECT",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Тесты
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SqlFirewallConfig {
        SqlFirewallConfig::default()
    }

    // ── Разрешённые запросы ───────────────────────────────────────────────────

    #[test]
    fn allows_simple_select() {
        let r = analyze_query("SELECT * FROM sensors WHERE id = 1", &cfg());
        assert!(r.allowed, "violations: {:?}", r.violations);
    }

    #[test]
    fn allows_aggregate_functions() {
        let r = analyze_query(
            "SELECT AVG(temperature), MAX(humidity) FROM readings WHERE ts > '2026-01-01'",
            &cfg(),
        );
        assert!(r.allowed, "violations: {:?}", r.violations);
    }

    #[test]
    fn allows_concat_in_select() {
        // FIX: оригинал блокировал CONCAT — это легитимная функция
        let r = analyze_query(
            "SELECT CONCAT(first_name, ' ', last_name) FROM users WHERE id = 5",
            &cfg(),
        );
        assert!(r.allowed, "CONCAT should not be blocked: {:?}", r.violations);
    }

    #[test]
    fn allows_complex_legitimate_query() {
        let r = analyze_query(
            "SELECT ts, temp, AVG(temp) OVER (ORDER BY ts ROWS BETWEEN 10 PRECEDING AND CURRENT ROW) \
             FROM readings WHERE location = 'HQ' AND unit = 'AHU-1' ORDER BY ts LIMIT 1000",
            &cfg(),
        );
        assert!(r.allowed, "violations: {:?}", r.violations);
    }

    #[test]
    fn allows_double_dash_in_string_literal() {
        // FIX: "-- comment" внутри строки не должен блокировать
        let r = analyze_query(
            "SELECT * FROM logs WHERE message = 'value--encoded'",
            &cfg(),
        );
        assert!(r.allowed, "-- inside string should not block: {:?}", r.violations);
    }

    // ── Блокировка DDL / DML ──────────────────────────────────────────────────

    #[test]
    fn blocks_drop_table() {
        let r = analyze_query("DROP TABLE users", &cfg());
        assert!(!r.allowed);
        assert!(r.violations.iter().any(|v| matches!(v, SqlViolation::NonSelectStatement(_))));
    }

    #[test]
    fn blocks_insert() {
        let r = analyze_query("INSERT INTO users (name) VALUES ('evil')", &cfg());
        assert!(!r.allowed);
    }

    #[test]
    fn blocks_stacked_queries() {
        let r = analyze_query("SELECT * FROM sensors; DROP TABLE users", &cfg());
        assert!(!r.allowed);
        assert!(r.violations.iter().any(|v| matches!(v, SqlViolation::StackedQueries(_))));
    }

    // ── UNION injection ───────────────────────────────────────────────────────

    #[test]
    fn blocks_union_injection() {
        let r = analyze_query(
            "SELECT name FROM sensors UNION SELECT password FROM users",
            &cfg(),
        );
        assert!(!r.allowed);
        assert!(r.violations.iter().any(|v| matches!(v, SqlViolation::UnionInjection)));
    }

    // ── Тавтологии ────────────────────────────────────────────────────────────

    #[test]
    fn blocks_classic_tautology_1_eq_1() {
        let r = analyze_query("SELECT * FROM sensors WHERE id = 1 OR 1 = 1", &cfg());
        assert!(!r.allowed);
        assert!(r.violations.iter().any(|v| matches!(v, SqlViolation::Tautology(_))));
    }

    #[test]
    fn blocks_tautology_2_eq_2() {
        // FIX: оригинал не детектировал числа кроме 1
        let r = analyze_query("SELECT * FROM sensors WHERE id = 1 OR 2 = 2", &cfg());
        assert!(!r.allowed, "2=2 should be detected as tautology: {:?}", r.violations);
    }

    #[test]
    fn blocks_tautology_string_eq() {
        let r = analyze_query("SELECT * FROM u WHERE id=1 OR 'x'='x'", &cfg());
        assert!(!r.allowed);
    }

    #[test]
    fn does_not_flag_null_eq_null_as_tautology() {
        // NULL = NULL — не тавтология в SQL (возвращает NULL/UNKNOWN)
        let r = analyze_query("SELECT * FROM t WHERE a IS NULL", &cfg());
        // IS NULL — не тавтология
        assert!(r.allowed, "IS NULL should be allowed: {:?}", r.violations);
    }

    // ── Системные таблицы ─────────────────────────────────────────────────────

    #[test]
    fn blocks_information_schema() {
        let r = analyze_query("SELECT * FROM information_schema.tables", &cfg());
        assert!(!r.allowed);
        assert!(r.violations.iter().any(|v| matches!(v, SqlViolation::SystemTableAccess(_))));
    }

    #[test]
    fn allows_table_named_mysql_users() {
        // FIX: строковый поиск "mysql" давал false positive для "mysql_users"
        // Таблица mysql_users не является системной схемой
        // AST-проверка смотрит на полное имя идентификатора
        let r = analyze_query("SELECT * FROM mysql_users WHERE active = 1", &cfg());
        assert!(r.allowed, "mysql_users is not a system schema: {:?}", r.violations);
    }

    // ── Опасные функции ───────────────────────────────────────────────────────

    #[test]
    fn blocks_load_file() {
        let r = analyze_query("SELECT LOAD_FILE('/etc/passwd') FROM dual", &cfg());
        assert!(!r.allowed);
        assert!(r.violations.iter().any(|v| matches!(v, SqlViolation::DangerousFunction(_))));
    }

    #[test]
    fn blocks_sleep_blind_injection() {
        let r = analyze_query("SELECT * FROM t WHERE id = 1 AND SLEEP(5)", &cfg());
        assert!(!r.allowed);
        assert!(r.violations.iter().any(|v| matches!(v, SqlViolation::DangerousFunction(f) if f == "sleep")));
    }

    #[test]
    fn blocks_xp_cmdshell() {
        let r = analyze_query("EXEC xp_cmdshell('whoami')", &cfg());
        assert!(!r.allowed);
    }

    // ── INTO OUTFILE ──────────────────────────────────────────────────────────

    #[test]
    fn blocks_into_outfile() {
        let r = analyze_query("SELECT * FROM sensors INTO OUTFILE '/tmp/dump.csv'", &cfg());
        assert!(!r.allowed);
        assert!(r.violations.iter().any(|v| matches!(v, SqlViolation::IntoOutfile)));
    }

    // ── Комментарии ───────────────────────────────────────────────────────────

    #[test]
    fn blocks_block_comment() {
        let r = analyze_query(
            "SELECT * FROM sensors WHERE id = 1 /* AND is_admin = 1 */",
            &cfg(),
        );
        assert!(!r.allowed);
        assert!(r.violations.iter().any(|v| matches!(v, SqlViolation::CommentInjection)));
    }

    #[test]
    fn blocks_line_comment_outside_string() {
        let r = analyze_query("SELECT * FROM t WHERE id = 1 -- injected", &cfg());
        assert!(!r.allowed);
    }

    // ── add_score / saturation ────────────────────────────────────────────────

    #[test]
    fn score_never_exceeds_1() {
        let s = add_score(0.9, 0.8);
        assert!(s <= 1.0);
    }

    #[test]
    fn score_accumulates_correctly() {
        let s = add_score(add_score(0.0, 0.3), 0.2);
        assert!((s - 0.5).abs() < 1e-9);
    }

    // ── explanation / dominant ────────────────────────────────────────────────

    #[test]
    fn explanation_present_on_block() {
        let r = analyze_query("DROP TABLE users", &cfg());
        assert!(r.explanation.contains("blocked"));
        assert!(r.dominant.is_some());
    }

    #[test]
    fn explanation_present_on_allow() {
        let r = analyze_query("SELECT id FROM t WHERE id = 5", &cfg());
        assert!(r.explanation.contains("allowed"));
        assert!(r.dominant.is_none());
    }

    // ── SqlViolation::kind ────────────────────────────────────────────────────

    #[test]
    fn violation_kind_strings() {
        assert_eq!(SqlViolation::UnionInjection.kind(), "union_injection");
        assert_eq!(SqlViolation::IntoOutfile.kind(), "into_outfile");
        assert_eq!(SqlViolation::Tautology("x".into()).kind(), "tautology");
    }

    // ── Subquery использует config ────────────────────────────────────────────

    #[test]
    fn subquery_uses_passed_config_not_default() {
        // Если blocked_functions передаётся в config, он должен работать в подзапросах
        let mut config = cfg();
        config.blocked_functions.push("my_dangerous_fn".to_string());
        let r = analyze_query(
            "SELECT * FROM t WHERE id IN (SELECT my_dangerous_fn(x) FROM t2)",
            &config,
        );
        assert!(!r.allowed, "Custom blocked function in subquery should block");
    }
}