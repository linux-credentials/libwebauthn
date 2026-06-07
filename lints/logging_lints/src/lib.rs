#![feature(rustc_private)]
#![warn(unused_extern_crates)]

//! Custom dylint lints enforcing the libwebauthn logging policy (docs/logging.md).
//!
//! These run before macro expansion so they can inspect the tokens as written:
//!
//! - `tracing_message_interpolation`: a tracing event/span message must be a
//!   static string literal, never an interpolated or `format!`-built string.
//! - `print_macro_in_library`: no `print!`/`println!`/`eprint!`/`eprintln!`.
//! - `log_crate_macro`: no `log::` macros, use `tracing`.
//! - `sensitive_field_above_debug`: best-effort denylist of sensitive field
//!   names used at `info!` and above.

extern crate rustc_ast;
extern crate rustc_errors;
extern crate rustc_lint;
extern crate rustc_session;
extern crate rustc_span;

use rustc_ast::ast::{Expr, ExprKind, MacCall, Stmt, StmtKind};
use rustc_ast::token::{Delimiter, IdentIsRaw, LitKind, TokenKind};
use rustc_ast::tokenstream::{TokenStream, TokenTree};
use rustc_lint::{EarlyContext, EarlyLintPass, Lint, LintContext, LintStore};
use rustc_session::Session;
use rustc_span::{Span, Symbol};

dylint_linting::dylint_library!();

rustc_session::declare_tool_lint! {
    /// Tracing event and span messages must be static string literals. Dynamic
    /// data belongs in structured fields, not interpolated into the message.
    pub dylint::TRACING_MESSAGE_INTERPOLATION,
    Warn,
    "tracing message must be a static string literal, not interpolated or formatted"
}

rustc_session::declare_tool_lint! {
    /// The print family writes to stdout/stderr and bypasses tracing. Library
    /// code must use tracing.
    pub dylint::PRINT_MACRO_IN_LIBRARY,
    Warn,
    "use tracing instead of the print family in library code"
}

rustc_session::declare_tool_lint! {
    /// libwebauthn standardises on tracing. The `log` crate's macros must not be
    /// used.
    pub dylint::LOG_CRATE_MACRO,
    Warn,
    "use tracing instead of the log crate"
}

rustc_session::declare_tool_lint! {
    /// Best-effort check that sensitive-looking field names are not logged at
    /// info or above. Sensitive values belong at debug (length/presence) or
    /// trace (full).
    pub dylint::SENSITIVE_FIELD_ABOVE_DEBUG,
    Warn,
    "possibly sensitive field logged at info or above"
}

rustc_session::declare_lint_pass!(LoggingLints => [
    TRACING_MESSAGE_INTERPOLATION,
    PRINT_MACRO_IN_LIBRARY,
    LOG_CRATE_MACRO,
    SENSITIVE_FIELD_ABOVE_DEBUG,
]);

#[expect(clippy::no_mangle_with_rust_abi)]
#[unsafe(no_mangle)]
pub fn register_lints(_sess: &Session, lint_store: &mut LintStore) {
    lint_store.register_lints(&[
        TRACING_MESSAGE_INTERPOLATION,
        PRINT_MACRO_IN_LIBRARY,
        LOG_CRATE_MACRO,
        SENSITIVE_FIELD_ABOVE_DEBUG,
    ]);
    lint_store.register_pre_expansion_pass(|| Box::new(LoggingLints));
}

const TRACING_MACROS: &[&str] = &["trace", "debug", "info", "warn", "error", "event", "span"];
const HIGH_LEVELS: &[&str] = &["info", "warn", "error"];
const PRINT_MACROS: &[&str] = &["print", "println", "eprint", "eprintln"];
const LOG_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];

/// Whole underscore-separated components that mark a field as sensitive.
const SENSITIVE_WORDS: &[&str] = &["token"];
/// Components that, alongside a `pin` component, mean the field is PIN protocol
/// metadata (a version or capability) rather than a PIN value.
const PIN_BENIGN: &[&str] = &[
    "proto",
    "protos",
    "protocol",
    "protocols",
    "version",
    "versions",
    "support",
    "supported",
    "option",
    "options",
];
/// Substrings (underscores removed, lowercased) that mark a field as sensitive.
const SENSITIVE_SUBSTRINGS: &[&str] = &[
    "secret",
    "hmac",
    "salt",
    "passphrase",
    "password",
    "privatekey",
    "sharedsecret",
    "pinhash",
    "pintoken",
    "pinuvauthtoken",
    "pinuvauthparam",
    "credential",
    "userhandle",
    "seed",
    "prf",
    "puat",
];
/// Components that make a field a harmless metric (length, count) even when it
/// names a sensitive value.
const METRIC_WORDS: &[&str] = &["len", "length", "count", "size", "num", "idx", "index"];

impl EarlyLintPass for LoggingLints {
    fn check_expr(&mut self, cx: &EarlyContext<'_>, expr: &Expr) {
        if let ExprKind::MacCall(mac) = &expr.kind {
            check_mac(cx, mac);
        }
    }

    fn check_stmt(&mut self, cx: &EarlyContext<'_>, stmt: &Stmt) {
        if let StmtKind::MacCall(mac_stmt) = &stmt.kind {
            check_mac(cx, &mac_stmt.mac);
        }
    }
}

fn check_mac(cx: &EarlyContext<'_>, mac: &MacCall) {
    let segments = &mac.path.segments;
    let Some(name) = segments.last().map(|s| s.ident.name) else {
        return;
    };
    let name = name.as_str();
    let single = segments.len() == 1;
    let prev = (segments.len() >= 2).then(|| segments[segments.len() - 2].ident.name);
    let prev = prev.as_ref().map(Symbol::as_str);

    if PRINT_MACROS.contains(&name) && (single || prev == Some("std") || prev == Some("core")) {
        emit(
            cx,
            PRINT_MACRO_IN_LIBRARY,
            mac.path.span,
            format!("`{name}!` in library code"),
            "use a tracing macro instead; see docs/logging.md",
        );
        return;
    }

    if prev == Some("log") && LOG_LEVELS.contains(&name) {
        emit(
            cx,
            LOG_CRATE_MACRO,
            mac.path.span,
            format!("`log::{name}!` used"),
            "use the equivalent tracing macro; see docs/logging.md",
        );
        return;
    }

    let is_tracing = TRACING_MACROS.contains(&name) && (single || prev == Some("tracing"));
    if !is_tracing {
        return;
    }

    let segs = top_level_segments(&mac.args.tokens);
    let msg_index = segs.iter().position(|s| sole_str_literal(s).is_some());

    if let Some(i) = msg_index {
        if let Some((sym, span)) = sole_str_literal(&segs[i]) {
            if has_placeholder(sym.as_str()) {
                emit(
                    cx,
                    TRACING_MESSAGE_INTERPOLATION,
                    span,
                    "tracing message interpolates dynamic data".to_string(),
                    "use a static message and structured fields, e.g. \
                     info!(field = value, \"message\"); see docs/logging.md",
                );
            }
        }
    }
    if let Some(span) = format_macro_segment(&segs) {
        emit(
            cx,
            TRACING_MESSAGE_INTERPOLATION,
            span,
            "tracing message built with `format!`".to_string(),
            "use a static message and structured fields; see docs/logging.md",
        );
    }
    for seg in &segs {
        if let Some(span) = dynamic_message_field(seg) {
            emit(
                cx,
                TRACING_MESSAGE_INTERPOLATION,
                span,
                "tracing `message` field is not a static string literal".to_string(),
                "set the message to a static string literal; see docs/logging.md",
            );
        }
    }

    if HIGH_LEVELS.contains(&name) {
        for unit in field_units(&segs, msg_index) {
            if segment_has_metric(&unit) {
                continue;
            }
            if let Some((field, span)) = first_sensitive_ident(&unit) {
                emit(
                    cx,
                    SENSITIVE_FIELD_ABOVE_DEBUG,
                    span,
                    format!("possibly sensitive field `{field}` logged at `{name}!`"),
                    "log sensitive data only at debug! (length or presence) or \
                     trace! (full); see docs/logging.md",
                );
            }
        }
    }
}

fn emit(cx: &EarlyContext<'_>, lint: &'static Lint, span: Span, msg: String, help: &'static str) {
    cx.opt_span_lint(
        lint,
        Some(span),
        rustc_errors::DiagDecorator(|diag: &mut rustc_errors::Diag<'_, ()>| {
            diag.primary_message(msg);
            diag.help(help);
        }),
    );
}

/// Split a macro's token stream on top-level commas.
fn top_level_segments(tokens: &TokenStream) -> Vec<Vec<&TokenTree>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for tt in tokens.iter() {
        if let TokenTree::Token(tok, _) = tt {
            if tok.kind == TokenKind::Comma {
                out.push(std::mem::take(&mut cur));
                continue;
            }
        }
        cur.push(tt);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Field segments to inspect for sensitivity, descending into a `{ ... }` brace
/// block (the form the policy uses for two or more fields) so its inner fields
/// are checked too. The message segment is skipped.
fn field_units<'a>(
    segs: &[Vec<&'a TokenTree>],
    msg_index: Option<usize>,
) -> Vec<Vec<&'a TokenTree>> {
    let mut units = Vec::new();
    for (i, seg) in segs.iter().enumerate() {
        if Some(i) == msg_index {
            continue;
        }
        if let [TokenTree::Delimited(_, _, Delimiter::Brace, inner)] = seg[..] {
            units.extend(top_level_segments(inner));
        } else {
            units.push(seg.clone());
        }
    }
    units
}

/// If a segment is exactly one string literal, return its value and span.
fn sole_str_literal(seg: &[&TokenTree]) -> Option<(Symbol, Span)> {
    if let [TokenTree::Token(tok, _)] = seg {
        if let TokenKind::Literal(lit) = tok.kind {
            if matches!(lit.kind, LitKind::Str | LitKind::StrRaw(_)) {
                return Some((lit.symbol, tok.span));
            }
        }
    }
    None
}

/// True if a format string contains a `{...}` placeholder (ignoring `{{`/`}}`).
fn has_placeholder(s: &str) -> bool {
    s.replace("{{", "").replace("}}", "").contains('{')
}

/// Span of a `format!`/`format_args!` call appearing as a top-level segment.
fn format_macro_segment(segs: &[Vec<&TokenTree>]) -> Option<Span> {
    for seg in segs {
        if let [TokenTree::Token(t0, _), TokenTree::Token(t1, _), ..] = seg[..] {
            if t1.kind == TokenKind::Bang {
                if let TokenKind::Ident(sym, IdentIsRaw::No) = t0.kind {
                    if matches!(sym.as_str(), "format" | "format_args") {
                        return Some(t0.span);
                    }
                }
            }
        }
    }
    None
}

/// True if the tokens are exactly one string literal.
fn is_static_str_value(value: &[&TokenTree]) -> bool {
    if let [TokenTree::Token(tok, _)] = value {
        if let TokenKind::Literal(lit) = tok.kind {
            return matches!(lit.kind, LitKind::Str | LitKind::StrRaw(_));
        }
    }
    false
}

/// Span of a `message = <value>` field whose value is not a static string
/// literal (e.g. `message = %x` or `message = format!(...)`), which sets a
/// dynamic event message and bypasses the static-message rule.
fn dynamic_message_field(seg: &[&TokenTree]) -> Option<Span> {
    if seg.len() < 2 {
        return None;
    }
    if let (TokenTree::Token(t0, _), TokenTree::Token(t1, _)) = (seg[0], seg[1]) {
        if t1.kind == TokenKind::Eq {
            if let TokenKind::Ident(sym, IdentIsRaw::No) = t0.kind {
                if sym.as_str() == "message" && !is_static_str_value(&seg[2..]) {
                    return Some(t0.span);
                }
            }
        }
    }
    None
}

fn ident_tokens(seg: &[&TokenTree]) -> Vec<(Symbol, Span)> {
    seg.iter()
        .filter_map(|tt| {
            if let TokenTree::Token(tok, _) = tt {
                if let TokenKind::Ident(sym, _) = tok.kind {
                    return Some((sym, tok.span));
                }
            }
            None
        })
        .collect()
}

fn segment_has_metric(seg: &[&TokenTree]) -> bool {
    ident_tokens(seg)
        .iter()
        .any(|(sym, _)| name_has_word(sym.as_str(), METRIC_WORDS))
}

fn first_sensitive_ident(seg: &[&TokenTree]) -> Option<(String, Span)> {
    ident_tokens(seg)
        .into_iter()
        .find(|(sym, _)| is_sensitive(sym.as_str()))
        .map(|(sym, span)| (sym.to_string(), span))
}

fn name_has_word(name: &str, words: &[&str]) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.split('_').any(|part| words.contains(&part))
}

fn is_sensitive(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('_').collect();
    if parts.iter().any(|p| SENSITIVE_WORDS.contains(p)) {
        return true;
    }
    if parts.contains(&"pin") && !parts.iter().any(|p| PIN_BENIGN.contains(p)) {
        return true;
    }
    let norm = lower.replace('_', "");
    SENSITIVE_SUBSTRINGS.iter().any(|s| norm.contains(s))
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
