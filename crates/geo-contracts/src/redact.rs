//! Secret references and redaction.
//!
//! Plans and artifacts carry `${geo-secret:<id>}` in place of a secret value.
//! Classification is deliberately broad: a false positive only hides a value
//! from records (it still resolves at execution); a false negative leaks it.

use crate::codec::Id;
use std::collections::BTreeMap;

const OPEN: &str = "${geo-secret:";

pub fn placeholder(id: &Id) -> String {
    format!("{OPEN}{id}}}")
}

/// Setting names that conventionally hold credentials.
pub fn is_secret_key(name: &str) -> bool {
    let n = name.to_ascii_uppercase().replace(['-', '.'], "_");
    const MARKS: &[&str] = &[
        "PASS",
        "PWD",
        "SECRET",
        "TOKEN",
        "APIKEY",
        "API_KEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
        "AUTH",
        "SIGNING_KEY",
        "SESSION_KEY",
        "COOKIE",
        "DSN",
        "WEBHOOK",
    ];
    MARKS.iter().any(|m| n.contains(m))
}

/// Values that look like credentials whatever their setting is called.
pub fn looks_like_credential(v: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "sk_live_",
        "sk_test_",
        "rk_live_",
        "rk_test_",
        "whsec_",
        "ghp_",
        "gho_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "sk-",
        "AIza",
        "-----BEGIN",
    ];
    let aws = v.len() == 20 && v.starts_with("AKIA") && v.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    let bearer = v.len() > 7 && v[..7].eq_ignore_ascii_case("bearer ");
    PREFIXES.iter().any(|p| v.starts_with(p)) || aws || bearer || v.matches('.').count() == 2 && v.starts_with("eyJ")
}

/// `scheme://user:password@host...` -> (text with the password replaced by
/// `with`, password). None when there is no password in the authority.
pub fn split_url_password(v: &str, with: &str) -> Option<(String, String)> {
    let start = v.find("://")? + 3;
    let rest = &v[start..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let at = rest[..end].rfind('@')?;
    let colon = rest[..at].find(':')?;
    let pw = &rest[colon + 1..at];
    if pw.is_empty() || pw.starts_with(OPEN) {
        return None;
    }
    Some((format!("{}{}{}", &v[..start + colon + 1], with, &v[start + at..]), pw.to_string()))
}

/// Replace every `${geo-secret:<id>}` with its value. Unknown ids are an
/// error: a placeholder is never passed on as if it were the value.
pub fn resolve(text: &str, secrets: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = rest.find(OPEN) {
        out.push_str(&rest[..i]);
        let after = &rest[i + OPEN.len()..];
        let j = after.find('}').ok_or_else(|| "unterminated secret reference".to_string())?;
        let id = &after[..j];
        out.push_str(secrets.get(id).ok_or_else(|| format!("secret {id} is not available to this execution"))?);
        rest = &after[j + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Replace known secret values in free text (logs, transcripts, payloads).
/// Longer values first, so a secret containing another is fully hidden.
pub fn redact_text(text: &str, secrets: &BTreeMap<String, String>) -> String {
    let mut vals: Vec<(&String, &String)> = secrets.iter().filter(|(_, v)| v.len() >= 4).collect();
    vals.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
    let mut out = text.to_string();
    for (id, v) in vals {
        out = out.replace(v.as_str(), &format!("{OPEN}{id}}}"));
    }
    out
}
