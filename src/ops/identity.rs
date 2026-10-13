//! 迁移和注销 —— 一个 DID 的结束方式,两种。
//!
//! 两者的区别只有一个:**有没有后继**。
//!
//! - **迁移**:这个 DID 死了,但它指向一个新 DID。走这条路的人会跟过去。
//! - **注销**:这个 DID 死了,没有然后。链在这里到头。
//!
//! 共同点是"旧文档不得删除、继续可解析" —— 一份被删掉的文档在验证方眼里
//! 和"这个 DID 从来不存在"完全一样,而它其实存在过、并且用它签过东西。

use std::path::Path;

use crate::audit::Event;
use crate::did::lifecycle;
use crate::did::migrate;
use crate::error::{KeydError, Result};
use crate::ops::{hosting_notice, sign_confirm_and_write, Session};

/// 迁移到一个新 DID。
pub struct Migrate {
    pub did: String,
    pub to: String,
    /// 允许后继的 stable subject path 和现在这个不一样(换域名)。
    pub allow_different_subject: bool,
}

pub fn migrate(root: Option<&Path>, args: Migrate) -> Result<()> {
    let mut session = Session::open(root)?;
    let (document, expected) = session.current_document(&args.did)?;

    // 环检测的输入是本机**所有**能读到的文档。离线查不到全网链,所以这里
    // 只能诚实地回答"我看得见的那部分里有没有环" —— 而那已经能挡住最常见的
    // 那个事故:两台机器互相把对方设成后继。
    let known = migrate::known_successors(session.layout())?;
    let planned = migrate::plan(
        &args.did,
        &args.to,
        &document,
        &known,
        args.allow_different_subject,
    )?;

    // 后继那个 DID 本机有没有文档,是"我知不知道自己迁去哪"的直接证据。
    // 没有就**不是错误** —— 迁到另一台机器上的 DID 是正常用法 —— 但它必须
    // 说出来:一个打错字的 `--to` 会在这里现形。
    let successor_is_local = crate::keystore::store::read_did_document(session.layout(), &args.to).is_ok();

    let same_subject = lifecycle::same_subject(&args.did, &args.to)?;

    let binding_passphrase = session.ask_secret(&format!(
        "Passphrase for {} (its binding key): ",
        args.did
    ))?;
    let (_, binding) = session.unlock_with(&args.did, None, binding_passphrase.as_bytes())?;

    if !successor_is_local {
        session.say(&format!(
            "\nwarning: {} has no document on this machine, so nothing here can tell you\n\
             whether it is really yours. Check that DID before going on.\n",
            args.to
        ))?;
    }
    if !same_subject {
        session.say(
            "\nwarning: these two DIDs have different stable subject paths, so as far as a\n\
             verifier is concerned they are different subjects. The link between them rests\n\
             entirely on the domain that serves each document — the spec calls this hop\n\
             `provider_asserted` and tells verifiers not to cache it.\n",
        )?;
    }

    let digest = sign_confirm_and_write(
        &session,
        &args.did,
        &binding,
        &planned,
        &expected,
        &format!(
            "Migrate {} → {}.\n\n\
             The document for the OLD DID is what gets rewritten, not deleted: it keeps its\n\
             keys and gains `deactivated: true` plus `successorDid`. The spec requires it to\n\
             stay parseable, because that is the only way anyone starting from the old DID\n\
             can find out where the subject went.\n\n\
             The successor edge is written ONCE and never rewritten. Nothing about the new\n\
             DID's own document changes here — and no secret moves anywhere.",
            args.did, args.to
        ),
    )?;

    session.audit(&Event::Migrate {
        did: args.did.clone(),
        successor: args.to.clone(),
        document_digest: digest,
        same_subject,
    })?;

    println!("{} is now deactivated and points at {}", args.did, args.to);
    println!();
    println!("republish BOTH documents:");
    hosting_notice(&args.did)?;
    hosting_notice(&args.to)?;
    println!();
    println!("and note: the old DID's key is still on this machine and still opens. It is");
    println!("deactivated in the document, not destroyed — anyone holding it can still sign,");
    println!("it just no longer resolves to a live DID.");
    Ok(())
}

/// 永久注销。也可以同时指向一个后继 —— 那其实就是迁移,只是不检查路径。
pub struct Deactivate {
    pub did: String,
    /// 给了就是"注销并指向它";不给就是彻底到头。
    pub to: Option<String>,
}

pub fn deactivate(root: Option<&Path>, args: Deactivate) -> Result<()> {
    let mut session = Session::open(root)?;
    let (document, expected) = session.current_document(&args.did)?;

    if let Some(to) = &args.to {
        if to == &args.did {
            return Err(KeydError::Did(format!(
                "{to} cannot succeed itself; use `deactivate` with no --to if you meant to \
                 end this DID without a successor"
            )));
        }
        // 只是解析一下:一个写错的 `--to` 会让 successorDid 指到一个谁也不认识
        // 的地方,而那条边**写下去就改不了了**。
        crate::did::parse::parse_did_wba(to).map_err(|error| {
            KeydError::Did(format!("--to {to} is not a did:wba DID: {error}"))
        })?;
    }

    // 已经注销过就拒绝,理由不是"文档会坏",而是**审计会撒谎**。再来一次
    // 得到的是同一份文档(Ed25519 是确定性的,签出来逐字节相同),却会在审计
    // 日志里留下一条"某时刻注销了它"的记录 —— 而那一刻什么也没发生。
    // 审计日志的价值全在于它记的都是真事。
    if lifecycle::is_deactivated(&document) {
        return Err(KeydError::Did(format!(
            "{} is already deactivated ({}). Running this again would change nothing, \
             so it is refused rather than leaving an audit record saying a deactivation \
             happened when none did.",
            args.did,
            match lifecycle::successor_of(&document) {
                Some(to) => format!("it points at {to}"),
                None => "it has no successor".to_string(),
            }
        )));
    }

    let planned = lifecycle::deactivate(&document, args.to.as_deref())?;

    let binding_passphrase = session.ask_secret(&format!(
        "Passphrase for {} (its binding key): ",
        args.did
    ))?;
    let (_, binding) = session.unlock_with(&args.did, None, binding_passphrase.as_bytes())?;

    let what = match &args.to {
        Some(to) => format!(
            "Deactivate {}, pointing at {to}.\n\n\
             This writes the successor edge, and that edge may only be written once — a\n\
             document that already has one will be refused rather than rewritten. If you\n\
             want the loop check and the subject-path check that `migrate` does, use\n\
             `migrate` instead; this command deliberately does neither.",
            args.did
        ),
        None => format!(
            "Deactivate {} permanently, with no successor.\n\n\
             This is the end of the line: nobody starting from this DID will be told where\n\
             the subject went, because it did not go anywhere. There is no undeactivate.",
            args.did
        ),
    };

    let digest =
        sign_confirm_and_write(&session, &args.did, &binding, &planned, &expected, &what)?;

    session.audit(&Event::Deactivate {
        did: args.did.clone(),
        successor: args.to.clone(),
        document_digest: digest,
    })?;

    match &args.to {
        Some(to) => println!("{} is deactivated and points at {to}", args.did),
        None => println!("{} is deactivated, with no successor", args.did),
    }
    hosting_notice(&args.did)
}
