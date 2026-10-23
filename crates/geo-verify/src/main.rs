//! `geo-verify PACK.json [--anchor ANCHOR.json]... [--require-profile classical|pq|hybrid] [--json]`
//!
//! Exit codes: 0 verified against the anchor, 1 invalid, 2 incomplete,
//! 3 unverifiable (no usable anchor, or none that carries the signatures the
//! profile you require needs), 64 bad usage or unreadable input.
//!
//! `geo-verify assessment BUNDLE [--trust-key KEY.json]... [--key-log LOG]
//! [--status STATUS.json] [--anchor ANCHOR.json]... [--pack PACK.json]... [--expect-revision D]
//! [--expect-rule ID=D]... [--max-status-age SECONDS] [--now MS]
//! [--require-current] [--require-profile classical|pq|hybrid] [--json]` checks
//! an assessment bundle (a directory with bundle.json, a bundle.json file, or
//! a bare assessment). Exit codes: 0 unchanged and signed with a key you
//! trust, 1 changed, wrongly signed or not what you expected, 3 unsigned, no
//! key you trust or (with `--require-profile`) not signed with every suite the
//! profile needs, 2 (only with `--require-current`) it may no longer apply,
//! 64 bad usage.

use geo_contracts::{
    Anchor, AssessmentStatusReport, AssessmentTrustPolicy, AssessmentTrustedKey, Canon, Digest, EvidencePack, Id,
    KeyEvent,
};
use geo_verify::suite::Policy;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The reader's own signature policy from `--require-profile`, or what the record requires.
fn require_profile(name: Option<&str>, bad: fn(&str) -> !) -> Policy {
    match name {
        None => Policy::any(),
        Some(n) => {
            Policy::profile(n).unwrap_or_else(|| bad(&format!("unknown profile {n}: use classical, pq or hybrid")))
        }
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("assessment") {
        args.remove(0);
        assessment(args);
    }
    let mut pack: Option<String> = None;
    let mut anchors: Vec<String> = vec![];
    let mut json = false;
    let mut profile: Option<String> = None;
    let mut args = args.into_iter();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--anchor" => match args.next() {
                Some(p) => anchors.push(p),
                None => usage("--anchor needs a file"),
            },
            "--require-profile" => match args.next() {
                Some(p) => profile = Some(p),
                None => usage("--require-profile needs classical, pq or hybrid"),
            },
            "--json" => json = true,
            "-h" | "--help" => usage(""),
            s if s.starts_with('-') => usage(&format!("unknown option {s}")),
            s if pack.is_none() => pack = Some(s.to_string()),
            _ => usage("only one pack file"),
        }
    }
    let Some(pack) = pack else { usage("no pack file") };
    let policy = require_profile(profile.as_deref(), usage);
    let read = |p: &str| std::fs::read(p).unwrap_or_else(|e| die(&format!("{p}: {e}")));
    let anchor_bytes: Vec<Vec<u8>> = anchors.iter().map(|p| read(p)).collect();
    match geo_verify::verify_bytes_with(&read(&pack), &anchor_bytes, &policy) {
        Ok(r) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&r.to_json()).unwrap());
            } else {
                print!("{}", r.text());
            }
            std::process::exit(r.exit_code());
        }
        Err(e) => die(&e),
    }
}

fn read(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap_or_else(|e| die(&format!("{}: {e}", p.display())))
}

/// A key log as the key store writes it (one event per line) or as a JSON list.
fn key_log(bytes: &[u8]) -> Vec<KeyEvent> {
    let text = String::from_utf8_lossy(bytes);
    if text.trim_start().starts_with('[') {
        let v: Vec<serde_json::Value> =
            serde_json::from_str(&text).unwrap_or_else(|e| die(&format!("key log: not a JSON list: {e}")));
        v.iter()
            .map(|e| KeyEvent::decode(e.to_string().as_bytes()).unwrap_or_else(|e| die(&format!("key log: {e}"))))
            .collect()
    } else {
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| KeyEvent::decode(l.as_bytes()).unwrap_or_else(|e| die(&format!("key log: {e}"))))
            .collect()
    }
}

fn assessment(args: Vec<String>) -> ! {
    let mut target: Option<PathBuf> = None;
    let mut keys: Vec<AssessmentTrustedKey> = vec![];
    let mut log: Vec<KeyEvent> = vec![];
    let mut log_as_of: Option<u64> = None;
    let mut status: Option<geo_verify::assessment::StatusInput> = None;
    let mut anchors: Vec<Anchor> = vec![];
    let mut packs: Vec<EvidencePack> = vec![];
    let mut expected = geo_contracts::assessment::Expected::default();
    let mut expect = false;
    let mut max_age: Option<u64> = None;
    let mut now: Option<u64> = None;
    let mut json = false;
    let mut require_current = false;
    let mut profile: Option<String> = None;
    let mut it = args.into_iter();
    let need = |it: &mut std::vec::IntoIter<String>, what: &str| {
        it.next().unwrap_or_else(|| ausage(&format!("{what} needs a value")))
    };
    while let Some(a) = it.next() {
        match a.as_str() {
            "--trust-key" => {
                let p = PathBuf::from(need(&mut it, "--trust-key"));
                let k = AssessmentTrustedKey::decode(&read(&p))
                    .unwrap_or_else(|e| die(&format!("{}: not a key file: {e}", p.display())));
                keys.push(k);
            }
            "--key-log" => {
                let p = PathBuf::from(need(&mut it, "--key-log"));
                log = key_log(&read(&p));
                log_as_of = std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as u64);
            }
            "--status" => {
                let p = PathBuf::from(need(&mut it, "--status"));
                let r = AssessmentStatusReport::decode(&read(&p))
                    .unwrap_or_else(|e| die(&format!("{}: not a status file: {e}", p.display())));
                status = Some(geo_verify::assessment::StatusInput {
                    report: r,
                    source: format!("the status file {}", p.display()),
                    direct: false,
                });
            }
            "--anchor" => {
                let p = PathBuf::from(need(&mut it, "--anchor"));
                anchors.push(
                    Anchor::decode(&read(&p))
                        .unwrap_or_else(|e| die(&format!("{}: not an anchor file: {e}", p.display()))),
                );
            }
            "--pack" => {
                let p = PathBuf::from(need(&mut it, "--pack"));
                packs.push(
                    EvidencePack::decode(&read(&p))
                        .unwrap_or_else(|e| die(&format!("{}: not an evidence pack: {e}", p.display()))),
                );
            }
            "--expect-revision" => {
                let v = need(&mut it, "--expect-revision");
                expected.revision =
                    Some(Digest::parse(&v).unwrap_or_else(|| ausage("--expect-revision needs sha256:<64 hex>")));
                expect = true;
            }
            "--expect-rule" => {
                let v = need(&mut it, "--expect-rule");
                let (rid, d) = v.split_once('=').unwrap_or_else(|| ausage("--expect-rule needs ID=sha256:<64 hex>"));
                let rid = Id::new(rid).unwrap_or_else(|_| ausage("--expect-rule: not a rule id"));
                let d = Digest::parse(d).unwrap_or_else(|| ausage("--expect-rule needs ID=sha256:<64 hex>"));
                expected.rules.insert(rid, d);
                expect = true;
            }
            "--max-status-age" => {
                let v = need(&mut it, "--max-status-age");
                max_age = Some(v.parse::<u64>().unwrap_or_else(|_| ausage("--max-status-age needs seconds")) * 1000);
            }
            "--now" => {
                now = Some(need(&mut it, "--now").parse().unwrap_or_else(|_| ausage("--now needs milliseconds")))
            }
            "--json" => json = true,
            "--require-current" => require_current = true,
            "--require-profile" => profile = Some(need(&mut it, "--require-profile")),
            "-h" | "--help" => ausage(""),
            s if s.starts_with('-') => ausage(&format!("unknown option {s}")),
            s if target.is_none() => target = Some(PathBuf::from(s)),
            _ => ausage("only one bundle"),
        }
    }
    let Some(target) = target else { ausage("no bundle") };
    let require = require_profile(profile.as_deref(), ausage);
    let (dir, file) = if target.is_dir() {
        (target.clone(), target.join("bundle.json"))
    } else {
        (target.parent().map(Path::to_path_buf).unwrap_or_default(), target.clone())
    };
    let bundle =
        geo_verify::assessment::read_bundle(&read(&file)).unwrap_or_else(|e| die(&format!("{}: {e}", file.display())));
    let mut files: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    for f in &bundle.files {
        if let Some(p) = &f.path {
            let bytes = geo_verify::assessment::safe_path(p).then(|| std::fs::read(dir.join(p)).ok()).flatten();
            files.insert(p.clone(), bytes);
        }
    }
    let policy = AssessmentTrustPolicy {
        id: Id::new("command-line").expect("valid id"),
        keys,
        key_log: log,
        key_log_as_of_ms: log_as_of,
        max_status_age_ms: max_age,
    };
    let now = now.unwrap_or_else(|| {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    });
    let v = geo_verify::assessment::verify_with(
        &geo_verify::assessment::Inputs {
            bundle: &bundle,
            files: &files,
            policy: &policy,
            status: status.as_ref(),
            anchors: &anchors,
            packs: &packs,
            expected: expect.then_some(&expected),
            now_ms: now,
        },
        &require,
    );
    if json {
        let j: serde_json::Value = serde_json::from_slice(&v.encode()).unwrap_or_default();
        println!("{}", serde_json::to_string_pretty(&j).unwrap());
    } else {
        print!("{}", geo_verify::assessment::text(&v));
    }
    let mut code = geo_verify::assessment::exit_code(&v);
    if code == 0
        && require_current
        && v.standing.applicability != geo_contracts::AssessmentApplicability::CurrentForDeclaredSubject
    {
        code = 2;
    }
    std::process::exit(code)
}

fn ausage(why: &str) -> ! {
    if !why.is_empty() {
        eprintln!("geo-verify assessment: {why}");
    }
    eprintln!("usage: geo-verify assessment BUNDLE [--trust-key KEY.json]... [--key-log LOG] [--status STATUS.json]");
    eprintln!(
        "         [--anchor ANCHOR.json]... [--pack PACK.json]... [--expect-revision sha256:..] [--expect-rule ID=sha256:..]..."
    );
    eprintln!(
        "         [--max-status-age SECONDS] [--now MS] [--require-current] [--require-profile classical|pq|hybrid] [--json]"
    );
    eprintln!("Checks an assessment report: that it is unchanged, which of the keys you trust signed it, what it is");
    eprintln!(
        "about, which evidence is included, and whether recent status says it still applies. Keys come only from"
    );
    eprintln!("--trust-key and --key-log, never from the bundle. It does not rerun the assessment.");
    eprintln!("--require-profile hybrid also requires both an ed25519 and an ML-DSA-65 signature by keys you trust,");
    eprintln!("whatever the report says it needs; a report without them is not trusted (exit 3).");
    std::process::exit(64)
}

fn usage(why: &str) -> ! {
    if !why.is_empty() {
        eprintln!("geo-verify: {why}");
    }
    eprintln!("usage: geo-verify PACK.json [--anchor ANCHOR.json]... [--require-profile classical|pq|hybrid] [--json]");
    eprintln!("       geo-verify assessment BUNDLE [options]   (see geo-verify assessment --help)");
    eprintln!("Checks an exported evidence pack against anchors you kept elsewhere. It needs nothing else:");
    eprintln!("no Geometer home, database or network. Without an anchor the history is reported unverifiable.");
    eprintln!("--require-profile trusts only checkpoints and anchors signed with every suite that profile needs");
    eprintln!("(hybrid: ed25519 and ML-DSA-65), whatever the key log asked for; others are reported unverifiable.");
    std::process::exit(64)
}

fn die(m: &str) -> ! {
    eprintln!("geo-verify: {m}");
    std::process::exit(64)
}
