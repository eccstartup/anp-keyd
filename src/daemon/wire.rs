//! socket 帧协议。
//!
//! 形状抄 ssh-agent:**长度前缀 + 类型字节**。
//!
//! ```text
//! frame   := u32_be(len) || payload
//! payload := u8(msg_type) || body
//! ```
//!
//! 类型编号自己定,**刻意不复用 SSH 的类型码** —— 复用了的话,一个走错门
//! 的 ssh 客户端会连上来然后收到莫名其妙的应答。
//!
//! 这个模块只做编解码,不碰密码学,也不碰 socket 生命周期。所以它可以
//! 在一对内存缓冲上完整地测 —— 协议这种东西出错的代价是"两个实现各说各话",
//! 而那种 bug 只有在联调时才发现,太晚了。

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use crate::error::{KeydError, Result};
use crate::keystore::record::KeyAlgorithm;

/// 一帧最多这么大。
///
/// 长度前缀是**对端给的**,而我们会照着它去分配内存 —— 不设上限的话,
/// 一句 `len = 0xFFFF_FFFF` 就能让守护进程当场去要 4GB。8 MiB 够放下
/// 请求体、消息头和一份 DID 文档,离"能拿来打人"还很远。
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

/// 请求体上限。比整帧小,好让头字段一定有地方放。
pub const MAX_BODY: usize = 4 * 1024 * 1024;

// —— 消息类型 ——

pub const LIST_KEYS: u8 = 0x01;
pub const SIGN: u8 = 0x02;
pub const UNLOCK: u8 = 0x03;
pub const LOCK: u8 = 0x04;
pub const STATUS: u8 = 0x05;
pub const OK: u8 = 0x80;
pub const ERR: u8 = 0x81;

/// 错误码。
///
/// **这个表比 [`KeydError`] 粗,是故意的。** 对端能看见的只有"哪一类错",
/// 看不见"哪个细节对不上" —— 尤其是口令:错口令和错 device.secret 在密码学上
/// 本来就分不出来,协议层也就不该假装能分。分得越细,越是给爆破的人送信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    /// 口令错,或者 device.secret 内容不对 —— **两者合并成一个码**。
    BadCredential = 0x0001,
    /// 信封的身份和它自称的不符(头部被改过)。
    AadMismatch = 0x0002,
    KeyNotFound = 0x0003,
    KeyExists = 0x0004,
    Locked = 0x0005,
    Permission = 0x0006,
    RawDisabled = 0x0007,
    /// 覆盖面被拒 —— 调用方要求的东西守护进程不签。
    CoveredSetRejected = 0x0008,
    /// 帧本身不合法(长度、类型、字段编码)。
    Protocol = 0x0009,
    Did = 0x000A,
    /// 守护进程自己出了问题。**消息文本要对调用方无信息量。**
    Internal = 0x00FF,
}

impl std::fmt::Display for ErrorCode {
    /// 给坐在终端前面的人看的短名。
    ///
    /// 这些码**本来就是线上的字节**,客户端一定拿得到 —— 把它们印出来
    /// 不泄露任何协议没说过的信息,而不印出来就只剩一句"被拒绝了",
    /// 人分不清是没解锁、口令错、还是没权限。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ErrorCode::BadCredential => "bad credential",
            ErrorCode::AadMismatch => "aad mismatch",
            ErrorCode::KeyNotFound => "key not found",
            ErrorCode::KeyExists => "key exists",
            ErrorCode::Locked => "locked",
            ErrorCode::Permission => "permission",
            ErrorCode::RawDisabled => "raw signing disabled",
            ErrorCode::CoveredSetRejected => "covered set rejected",
            ErrorCode::Protocol => "protocol",
            ErrorCode::Did => "did",
            ErrorCode::Internal => "internal",
        })
    }
}

impl ErrorCode {
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    pub fn from_u16(raw: u16) -> Option<Self> {
        use ErrorCode::*;
        Some(match raw {
            0x0001 => BadCredential,
            0x0002 => AadMismatch,
            0x0003 => KeyNotFound,
            0x0004 => KeyExists,
            0x0005 => Locked,
            0x0006 => Permission,
            0x0007 => RawDisabled,
            0x0008 => CoveredSetRejected,
            0x0009 => Protocol,
            0x000A => Did,
            0x00FF => Internal,
            _ => return None,
        })
    }
}

impl KeydError {
    /// 内部错误 → 对端能看见的错误码。
    pub fn wire_code(&self) -> ErrorCode {
        use KeydError::*;
        match self {
            BadPassphrase | BadDeviceSecret => ErrorCode::BadCredential,
            AadMismatch => ErrorCode::AadMismatch,
            KeyNotFound(_) => ErrorCode::KeyNotFound,
            KeyExists(_) => ErrorCode::KeyExists,
            Locked => ErrorCode::Locked,
            PeerCredentialUnavailable(_) | Permission(_) => ErrorCode::Permission,
            RawDisabled => ErrorCode::RawDisabled,
            CoveredSetRejected(_) => ErrorCode::CoveredSetRejected,
            Protocol(_) => ErrorCode::Protocol,
            Did(_) => ErrorCode::Did,
            Crypto(_) | Upstream(_) | Io(_) | Json(_) => ErrorCode::Internal,
            // 客户端把收到的粗码原样带回来。环是这样闭合的:服务端
            // `BadPassphrase → BadCredential`,客户端 `BadCredential →
            // Refused{code}`,再发出去还是 `BadCredential`。
            Refused { code, .. } => *code,
        }
    }

    /// 内部错误 → 对端能看见的错误消息。
    ///
    /// **这个方法存在的唯一理由是 [`KeydError::BadPassphrase`] 和
    /// [`KeydError::BadDeviceSecret`] 的 `Display` 不一样。** 直接
    /// `err.to_string()` 发出去,就等于在线上告诉对面"口令错了"还是
    /// "device.secret 错了" —— 而这两件事在密码学上本来就分不出来,
    /// 区分它们只是白白给爆破的人省一半力。所以这一对压成同一句话。
    pub fn wire_message(&self) -> String {
        match self {
            KeydError::BadPassphrase | KeydError::BadDeviceSecret => {
                "the credential was refused".to_string()
            }
            // `Refused` 已经是协议层的话,不再套一层 —— 否则消息会随着
            // 每一次转发越长,而最里面那一句才是真正有用的那一句。
            KeydError::Refused { message, .. } => message.clone(),
            other => other.to_string(),
        }
    }
}

// —— 请求 / 应答 ——

/// `SIGN` 的请求体。
///
/// 这是本设计里最重要的一个决定,所以它有两个变体而不是一个 `Vec<u8>`:
/// 主路径给的是**结构化字段**,签名基由守护进程自己拼;只有 `Raw` 才是
/// "你给字节我签",而那条路默认关着。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignRequest {
    /// 主路径。守护进程从这里重建签名基,并自己决定覆盖面下限。
    Structured {
        did: String,
        /// 要用的那个 fragment(`key-2`、`recovery-1`……)。不给 = `did` 名下
        /// 的默认那把(绑定密钥)。见 [`crate::keystore::store::resolve`]。
        kid: Option<String>,
        method: String,
        target_uri: String,
        headers: BTreeMap<String, String>,
        /// **请求体本身**,不是它的摘要。
        ///
        /// 计划草案这里写的是 `body_digest`,但那样守护进程就会去签一个
        /// **调用方给的**摘要值 —— 而"签名绑定到守护进程自己算出来的
        /// content-digest"正是防盲目签名的关键一环。摘要由我们算,
        /// 所以要拿到 body。
        ///
        /// 拿不动整份 body 的场景(大文件上传),那正是 `Raw` 存在的意义:
        /// 显式打开、逐条审计,而不是把结构化路径悄悄降级。
        body: Option<Vec<u8>>,
        /// 调用方**额外**要求覆盖的分量。只能加,不能减 —— 见
        /// [`crate::sign::rfc9421::SignRequest::covered`]。
        covered: Vec<String>,
    },
    /// 受限路径:原始字节。默认关,`--allow-raw-signing` 才开,且必留审计。
    Raw { did: String, kid: Option<String>, payload: Vec<u8> },
}

/// 一把钥匙在磁盘上的样子 —— `LIST_KEYS` 的应答项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySummary {
    pub did: String,
    pub kid: String,
    pub algorithm: KeyAlgorithm,
}

/// 一条连接上收到的请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    ListKeys,
    Sign(SignRequest),
    /// 解锁一把钥匙。`passphrase` 是**明文**,只在内存里活到用完为止。
    Unlock { did: String, kid: Option<String>, passphrase: String },
    /// 锁上。**两级**:`did` 为空表示全锁;只给 `did` 表示把这个 DID 底下
    /// 解锁着的全放掉;再给 `kid` 就是精确到一把。
    Lock { did: Option<String>, kid: Option<String> },
    Status,
}

/// 一条应答。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Ok,
    ListKeys(Vec<KeySummary>),
    /// `u16 sig_len ‖ sig`。Ed25519 的签名是 64 字节。
    Signature(Vec<u8>),
    Status(Vec<UnlockedKey>),
    Error { code: ErrorCode, message: String },
}

/// `STATUS` 里的一把已解锁钥匙。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockedKey {
    pub did: String,
    pub kid: String,
    /// 从解锁到现在过了多少秒。
    pub unlocked_secs: u64,
}

impl Response {
    /// **把内部错误翻译成对端能看见的东西的唯一入口。**
    ///
    /// 请求处理里不要手写 `Response::Error { code, message }`,走这里 ——
    /// 免得某一条分支顺手 `err.to_string()` 出去,把口令类错误的细节漏了。
    pub fn from_error(error: &KeydError) -> Self {
        Response::Error { code: error.wire_code(), message: error.wire_message() }
    }
}

// ————————————————————————————————————————————————————————————————————————
// 编解码
// ————————————————————————————————————————————————————————————————————————

/// 读一帧。返回 `Ok(None)` 表示对端在帧边界上干净地关了连接。
pub fn read_request<R: Read>(reader: &mut R) -> Result<Option<Request>> {
    let Some(payload) = read_frame(reader)? else {
        return Ok(None);
    };
    decode_request(&payload).map(Some)
}

/// 读一帧。返回 `Ok(None)` 表示对端在帧边界上干净地关了连接。
pub fn read_response<R: Read>(reader: &mut R) -> Result<Option<Response>> {
    let Some(payload) = read_frame(reader)? else {
        return Ok(None);
    };
    decode_response(&payload).map(Some)
}

/// 写一条应答。**写完 `flush`**,否则调用方会一直等一个躺在缓冲区里的字节。
pub fn write_response<W: Write>(writer: &mut W, response: &Response) -> Result<()> {
    let payload = encode_response(response)?;
    write_frame(writer, &payload)?;
    writer.flush()?;
    Ok(())
}

pub fn write_request<W: Write>(writer: &mut W, request: &Request) -> Result<()> {
    let payload = encode_request(request)?;
    write_frame(writer, &payload)?;
    writer.flush()?;
    Ok(())
}

fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        // 干净地关在帧边界上。
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(KeydError::Io(e)),
    }

    let len = u32::from_be_bytes(header) as usize;
    if len == 0 {
        return Err(KeydError::Protocol(
            "a zero-length frame carries no message type".into(),
        ));
    }
    if len > MAX_FRAME {
        return Err(KeydError::Protocol(format!(
            "frame of {len} bytes exceeds the {MAX_FRAME}-byte limit"
        )));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            // 说了 len 字节却只给了一半就断 —— 这不是干净关闭。
            KeydError::Protocol(format!("connection ended inside a {len}-byte frame"))
        } else {
            KeydError::Io(e)
        }
    })?;
    Ok(Some(payload))
}

fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<()> {
    if payload.is_empty() {
        return Err(KeydError::Protocol("refusing to write an empty frame".into()));
    }
    if payload.len() > MAX_FRAME {
        return Err(KeydError::Protocol(format!(
            "frame of {} bytes exceeds the {MAX_FRAME}-byte limit",
            payload.len()
        )));
    }
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(payload)?;
    Ok(())
}

// —— 请求 ——

fn decode_request(payload: &[u8]) -> Result<Request> {
    let (msg_type, body) = payload
        .split_first()
        .ok_or_else(|| KeydError::Protocol("empty frame".into()))?;

    match *msg_type {
        LIST_KEYS => {
            expect_empty(body, "LIST_KEYS")?;
            Ok(Request::ListKeys)
        }
        SIGN => decode_sign(body).map(Request::Sign),
        UNLOCK => {
            let mut c = Cursor::new(body);
            let did = c.string16()?;
            let kid = c.opt_string16()?;
            let passphrase = c.string16()?;
            c.expect_end("UNLOCK")?;
            Ok(Request::Unlock { did, kid, passphrase })
        }
        LOCK => {
            let mut c = Cursor::new(body);
            let did = c.string16()?;
            let kid = c.opt_string16()?;
            c.expect_end("LOCK")?;
            // 空字符串 = 全部锁上。
            Ok(Request::Lock { did: if did.is_empty() { None } else { Some(did) }, kid })
        }
        STATUS => {
            expect_empty(body, "STATUS")?;
            Ok(Request::Status)
        }
        other => Err(KeydError::Protocol(format!(
            "0x{other:02x} is not a request type this daemon accepts"
        ))),
    }
}

fn decode_sign(body: &[u8]) -> Result<SignRequest> {
    let mut c = Cursor::new(body);
    let tag = c.u8()?;
    match tag {
        0x01 => {
            let did = c.string16()?;
            let kid = c.opt_string16()?;
            let method = c.string16()?;
            let target_uri = c.string16()?;

            let count = c.u16()? as usize;
            let mut headers = BTreeMap::new();
            for _ in 0..count {
                let name = c.string16()?;
                let value = c.string16()?;
                // 同名头出现两次意味着其中一条会被悄悄丢弃 —— 而"哪个值
                // 进了签名基"会直接改变签名结果。不在协议层替调用方做选择。
                if headers.insert(name.clone(), value).is_some() {
                    return Err(KeydError::Protocol(format!(
                        "header {name:?} is given twice"
                    )));
                }
            }

            let body = c.opt_body()?;

            let covered_count = c.u16()? as usize;
            let mut covered = Vec::with_capacity(covered_count.min(64));
            for _ in 0..covered_count {
                covered.push(c.string16()?);
            }
            c.expect_end("SIGN(Structured)")?;

            Ok(SignRequest::Structured { did, kid, method, target_uri, headers, body, covered })
        }
        0x02 => {
            let did = c.string16()?;
            let kid = c.opt_string16()?;
            let payload = c.bytes32()?;
            c.expect_end("SIGN(Raw)")?;
            Ok(SignRequest::Raw { did, kid, payload })
        }
        other => Err(KeydError::Protocol(format!(
            "0x{other:02x} is not a SIGN variant"
        ))),
    }
}

// —— 应答 ——

fn decode_response(payload: &[u8]) -> Result<Response> {
    let (msg_type, body) = payload
        .split_first()
        .ok_or_else(|| KeydError::Protocol("empty frame".into()))?;

    match *msg_type {
        OK => {
            expect_empty(body, "OK")?;
            Ok(Response::Ok)
        }
        ERR => {
            let mut c = Cursor::new(body);
            let raw = c.u16()?;
            let code = ErrorCode::from_u16(raw).ok_or_else(|| {
                KeydError::Protocol(format!("0x{raw:04x} is not an error code this client knows"))
            })?;
            let message = c.string16()?;
            c.expect_end("ERR")?;
            Ok(Response::Error { code, message })
        }
        LIST_KEYS => {
            let mut c = Cursor::new(body);
            let count = c.u16()? as usize;
            let mut keys = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                let did = c.string16()?;
                let kid = c.string16()?;
                let algorithm = KeyAlgorithm::from_wire(c.u8()?).ok_or_else(|| {
                    KeydError::Protocol("unknown key algorithm byte".into())
                })?;
                keys.push(KeySummary { did, kid, algorithm });
            }
            c.expect_end("LIST_KEYS")?;
            Ok(Response::ListKeys(keys))
        }
        SIGN => {
            let mut c = Cursor::new(body);
            let signature = c.bytes16()?;
            c.expect_end("SIGN")?;
            Ok(Response::Signature(signature))
        }
        STATUS => {
            let mut c = Cursor::new(body);
            let count = c.u16()? as usize;
            let mut keys = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                let did = c.string16()?;
                let kid = c.string16()?;
                let unlocked_secs = c.u64()?;
                keys.push(UnlockedKey { did, kid, unlocked_secs });
            }
            c.expect_end("STATUS")?;
            Ok(Response::Status(keys))
        }
        other => Err(KeydError::Protocol(format!(
            "0x{other:02x} is not a response type this client knows"
        ))),
    }
}

fn encode_request(request: &Request) -> Result<Vec<u8>> {
    let mut body = Encoder::default();
    let msg_type = match request {
        Request::ListKeys => LIST_KEYS,
        Request::Status => STATUS,
        Request::Sign(sign) => {
            match sign {
                SignRequest::Structured {
                    did,
                    kid,
                    method,
                    target_uri,
                    headers,
                    body: request_body,
                    covered,
                } => {
                    body.push(0x01);
                    body.string16(did)?;
                    body.string16(kid.as_deref().unwrap_or(""))?;
                    body.string16(method)?;
                    body.string16(target_uri)?;
                    body.u16(u16::try_from(headers.len())
                        .map_err(|_| KeydError::Protocol("too many headers".into()))?);
                    for (name, value) in headers {
                        body.string16(name)?;
                        body.string16(value)?;
                    }
                    body.opt_body(request_body.as_deref())?;
                    body.u16(u16::try_from(covered.len())
                        .map_err(|_| KeydError::Protocol("too many covered components".into()))?);
                    for component in covered {
                        body.string16(component)?;
                    }
                }
                SignRequest::Raw { did, kid, payload } => {
                    body.push(0x02);
                    body.string16(did)?;
                    body.string16(kid.as_deref().unwrap_or(""))?;
                    body.bytes32(payload)?;
                }
            }
            SIGN
        }
        Request::Unlock { did, kid, passphrase } => {
            body.string16(did)?;
            body.string16(kid.as_deref().unwrap_or(""))?;
            body.string16(passphrase)?;
            UNLOCK
        }
        Request::Lock { did, kid } => {
            body.string16(did.as_deref().unwrap_or(""))?;
            body.string16(kid.as_deref().unwrap_or(""))?;
            LOCK
        }
    };

    // 类型字节在最前面。
    let mut payload = Encoder::with_capacity(body.len() + 1);
    payload.push(msg_type);
    payload.extend(body.as_slice());
    Ok(payload.into_vec())
}

fn encode_response(response: &Response) -> Result<Vec<u8>> {
    let mut body = Encoder::default();
    let msg_type = match response {
        Response::Ok => OK,
        Response::Error { code, message } => {
            body.u16(code.as_u16());
            // 错误消息的长度也是 u16,太长的消息会被截断成半句话 ——
            // 与其截断,不如在编码这一层就拒掉,这样是"发不出去",
            // 而不是"发出去一条读着像别的东西的消息"。
            body.string16(message).map_err(|_| {
                KeydError::Protocol("the error message is too long for the wire".into())
            })?;
            ERR
        }
        Response::ListKeys(keys) => {
            body.u16(u16::try_from(keys.len()).map_err(|_| {
                KeydError::Protocol("too many keys for one LIST_KEYS response".into())
            })?);
            for key in keys {
                body.string16(&key.did)?;
                body.string16(&key.kid)?;
                body.push(key.algorithm.to_wire());
            }
            LIST_KEYS
        }
        Response::Signature(signature) => {
            body.bytes16(signature)?;
            SIGN
        }
        Response::Status(keys) => {
            body.u16(u16::try_from(keys.len()).map_err(|_| {
                KeydError::Protocol("too many keys for one STATUS response".into())
            })?);
            for key in keys {
                body.string16(&key.did)?;
                body.string16(&key.kid)?;
                body.u64(key.unlocked_secs);
            }
            STATUS
        }
    };

    let mut payload = Encoder::with_capacity(body.len() + 1);
    payload.push(msg_type);
    payload.extend(body.as_slice());
    Ok(payload.into_vec())
}

// —— 字节层的小工具 ——

/// 顺序读一个 body。每一步都检查边界 —— 这一段处理的完全是**不可信输入**,
/// 越界读在这里等于把守护进程的地址空间交给对端。
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| KeydError::Protocol("length overflow".into()))?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| KeydError::Protocol("truncated frame body".into()))?;
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let raw = self.take(2)?;
        Ok(u16::from_be_bytes([raw[0], raw[1]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let raw = self.take(8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(raw);
        Ok(u64::from_be_bytes(buf))
    }

    fn string16(&mut self) -> Result<String> {
        let len = self.u16()? as usize;
        let raw = self.take(len)?;
        std::str::from_utf8(raw)
            .map(str::to_owned)
            .map_err(|_| KeydError::Protocol("a string field is not valid UTF-8".into()))
    }

    /// 空串 = "没给"。和 `Lock { did }` 一直以来的约定一致。
    ///
    /// 用空串而不是另加一个标志字节:fragment 永远不可能是空的(`key-1`
    /// 至少也有一个字符),所以空串不会和任何合法值撞上,而多一个标志字节
    /// 只是给每一种请求多一处可以编错的地方。
    fn opt_string16(&mut self) -> Result<Option<String>> {
        Ok(match self.string16()? {
            value if value.is_empty() => None,
            value => Some(value),
        })
    }

    fn bytes16(&mut self) -> Result<Vec<u8>> {
        let len = self.u16()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn bytes32(&mut self) -> Result<Vec<u8>> {
        let len = u32::from_be_bytes({
            let raw = self.take(4)?;
            [raw[0], raw[1], raw[2], raw[3]]
        }) as usize;
        if len > MAX_BODY {
            return Err(KeydError::Protocol(format!(
                "a {len}-byte payload exceeds the {MAX_BODY}-byte limit"
            )));
        }
        Ok(self.take(len)?.to_vec())
    }

    /// `u32` 长度;`0xFFFF_FFFF` 表示"没有 body"。
    fn opt_body(&mut self) -> Result<Option<Vec<u8>>> {
        let raw = self.take(4)?;
        let len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        if len == u32::MAX {
            return Ok(None);
        }
        let len = len as usize;
        if len > MAX_BODY {
            return Err(KeydError::Protocol(format!(
                "a {len}-byte body exceeds the {MAX_BODY}-byte limit"
            )));
        }
        Ok(Some(self.take(len)?.to_vec()))
    }

    /// 尾部多出来的字节是协议不一致的信号,不是可以忽略的填充。
    fn expect_end(&self, what: &str) -> Result<()> {
        if self.at != self.bytes.len() {
            return Err(KeydError::Protocol(format!(
                "{what} has {} trailing bytes",
                self.bytes.len() - self.at
            )));
        }
        Ok(())
    }
}

/// 顺序写一个 body。每一个带长度的字段都在写入时检查**值域**:编码不出去
/// 的音高(field 长过 u16)在写入这一刻就报错,而不是在线上被悄悄截断。
#[derive(Default)]
struct Encoder {
    out: Vec<u8>,
}

impl Encoder {
    fn with_capacity(capacity: usize) -> Self {
        Self { out: Vec::with_capacity(capacity) }
    }

    fn push(&mut self, byte: u8) {
        self.out.push(byte);
    }

    fn len(&self) -> usize {
        self.out.len()
    }

    fn as_slice(&self) -> &[u8] {
        &self.out
    }

    fn extend(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    fn into_vec(self) -> Vec<u8> {
        self.out
    }

    fn u16(&mut self, value: u16) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn string16(&mut self, value: &str) -> Result<()> {
        let len = u16::try_from(value.len()).map_err(|_| {
            KeydError::Protocol(format!("a {} byte string field does not fit in u16", value.len()))
        })?;
        self.u16(len);
        self.out.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn bytes16(&mut self, value: &[u8]) -> Result<()> {
        let len = u16::try_from(value.len()).map_err(|_| {
            KeydError::Protocol(format!("a {} byte field does not fit in u16", value.len()))
        })?;
        self.u16(len);
        self.out.extend_from_slice(value);
        Ok(())
    }

    fn bytes32(&mut self, value: &[u8]) -> Result<()> {
        if value.len() > MAX_BODY {
            return Err(KeydError::Protocol(format!(
                "a {} byte payload exceeds the {MAX_BODY}-byte limit",
                value.len()
            )));
        }
        self.out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.out.extend_from_slice(value);
        Ok(())
    }

    /// `0xFFFF_FFFF` 表示"没有 body",和"body 是空串"分开编码。
    fn opt_body(&mut self, value: Option<&[u8]>) -> Result<()> {
        match value {
            Some(body) => self.bytes32(body),
            None => {
                self.out.extend_from_slice(&u32::MAX.to_be_bytes());
                Ok(())
            }
        }
    }
}

fn expect_empty(body: &[u8], what: &str) -> Result<()> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(KeydError::Protocol(format!(
            "{what} takes no body, but {} bytes follow the type byte",
            body.len()
        )))
    }
}

/// 守护进程和客户端之间的一次一问一答,跑在一个已经建立的双向流上。
pub fn round_trip<S: Read + Write>(stream: &mut S, request: &Request) -> Result<Response> {
    write_request(stream, request)?;
    match read_response(stream)? {
        Some(response) => Ok(response),
        // 应答之前就断,不是"对端没有应答",而是对端坏了。
        None => Err(KeydError::Protocol(
            "the connection closed before a response arrived".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_request(request: &Request) -> Request {
        let mut wire = Vec::new();
        write_request(&mut wire, request).unwrap();

        // 真的走一遍字节,而不是直接调 decode —— 那样才测得到长度前缀。
        let mut reader = std::io::Cursor::new(wire);
        read_request(&mut reader).unwrap().unwrap()
    }

    fn round_trip_response(response: &Response) -> Response {
        let mut wire = Vec::new();
        write_response(&mut wire, response).unwrap();

        let mut reader = std::io::Cursor::new(wire);
        read_response(&mut reader).unwrap().unwrap()
    }

    fn structured() -> SignRequest {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("x-request-id".to_string(), "abc".to_string());
        SignRequest::Structured {
            kid: None,
            did: "did:wba:example.com:user:alice:e1_abc".into(),
            method: "POST".into(),
            target_uri: "https://example.com/api".into(),
            headers,
            body: Some(b"{\"hello\":1}".to_vec()),
            covered: vec!["content-type".into()],
        }
    }

    #[test]
    fn every_request_survives_a_round_trip() {
        let requests = [
            Request::ListKeys,
            Request::Status,
            Request::Sign(structured()),
            Request::Sign(SignRequest::Raw {
                did: "did:wba:x".into(),
                kid: None,
                payload: vec![0, 1, 2],
            }),
            Request::Unlock {
                did: "did:wba:x".into(),
                kid: None,
                passphrase: "hunter2".into(),
            },
            Request::Lock { did: Some("did:wba:x".into()), kid: None },
            Request::Lock { did: None, kid: None },
        ];

        for request in requests {
            assert_eq!(round_trip_request(&request), request, "{request:?}");
        }
    }

    #[test]
    fn every_response_survives_a_round_trip() {
        let responses = [
            Response::Ok,
            Response::ListKeys(vec![KeySummary {
                did: "did:wba:x".into(),
                kid: "did:wba:x#key-1".into(),
                algorithm: KeyAlgorithm::Ed25519,
            }]),
            Response::Signature(vec![7u8; 64]),
            Response::Status(vec![UnlockedKey {
                did: "did:wba:x".into(),
                kid: "did:wba:x#key-1".into(),
                unlocked_secs: 42,
            }]),
            Response::Error { code: ErrorCode::BadCredential, message: "bad".into() },
        ];

        for response in responses {
            assert_eq!(round_trip_response(&response), response, "{response:?}");
        }
    }

    /// 没有 body 和"body 是空串"是两回事,不能压成同一个值 ——
    /// 前者不覆盖 `content-digest`,后者要覆盖。
    #[test]
    fn an_absent_body_is_not_an_empty_body() {
        let absent = SignRequest::Structured {
            did: "d".into(),
            kid: None,
            method: "GET".into(),
            target_uri: "https://e.com/".into(),
            headers: BTreeMap::new(),
            body: None,
            covered: Vec::new(),
        };
        let empty = match absent.clone() {
            SignRequest::Structured { did, kid, method, target_uri, headers, covered, .. } => {
                SignRequest::Structured {
                    did,
                    kid,
                    method,
                    target_uri,
                    headers,
                    body: Some(Vec::new()),
                    covered,
                }
            }
            _ => unreachable!(),
        };

        assert_eq!(round_trip_request(&Request::Sign(absent.clone())), Request::Sign(absent));
        assert_eq!(round_trip_request(&Request::Sign(empty.clone())), Request::Sign(empty));
    }

    /// 长度前缀是**对端给的**,我们会照着它分配内存。不设上限就是一条
    /// 让守护进程去要 4GB 的单行指令。
    #[test]
    fn a_frame_that_claims_to_be_enormous_is_refused_before_allocating() {
        let mut reader = std::io::Cursor::new(u32::MAX.to_be_bytes().to_vec());
        let err = read_request(&mut reader).unwrap_err();
        assert!(matches!(err, KeydError::Protocol(_)), "{err}");
        assert!(err.to_string().contains("limit"), "{err}");
    }

    #[test]
    fn a_zero_length_frame_is_refused() {
        let mut reader = std::io::Cursor::new(0u32.to_be_bytes().to_vec());
        assert!(read_request(&mut reader).is_err());
    }

    /// 说到一半断掉 ≠ 说完了。前者是坏消息,后者是"对端下班了"。
    #[test]
    fn a_truncated_body_is_not_a_clean_close() {
        let mut wire = Vec::new();
        write_request(&mut wire, &Request::ListKeys).unwrap();
        wire.truncate(wire.len() - 1);

        let mut reader = std::io::Cursor::new(wire);
        let err = read_request(&mut reader).unwrap_err();
        assert!(err.to_string().contains("inside"), "{err}");
    }

    #[test]
    fn a_clean_close_at_a_frame_boundary_is_not_an_error() {
        let mut reader = std::io::Cursor::new(Vec::new());
        assert_eq!(read_request(&mut reader).unwrap(), None);
        assert_eq!(read_response(&mut reader).unwrap(), None);
    }

    /// 对端说"这里有 10 字节",可帧里只剩 3 字节 —— 不能读出去,也不能
    /// 把那 3 字节当成一个短字段。
    #[test]
    fn a_field_that_runs_past_the_end_of_the_frame_is_refused() {
        let cases: Vec<Vec<u8>> = vec![
            // UNLOCK 里 did 声称有 100 字节
            vec![UNLOCK, 0x00, 100, b'd'],
            // SIGN 的类型字节后面什么都没有
            vec![SIGN],
            // SIGN(Structured) 声称有 5000 个头
            {
                let mut v = vec![SIGN, 0x01];
                v.extend_from_slice(&0u16.to_be_bytes()); // did
                v.extend_from_slice(&0u16.to_be_bytes()); // method
                v.extend_from_slice(&0u16.to_be_bytes()); // uri
                v.extend_from_slice(&5000u16.to_be_bytes()); // header count
                v
            },
        ];

        for payload in cases {
            let err = decode_request(&payload).unwrap_err();
            assert!(matches!(err, KeydError::Protocol(_)), "{payload:?} → {err}");
        }
    }

    /// 尾部多出字节说明两边对协议的理解已经不一致了 —— 不要猜,报错。
    #[test]
    fn trailing_bytes_are_refused() {
        let mut payload = vec![LIST_KEYS];
        payload.push(0xAA);
        assert!(decode_request(&payload).is_err());

        let mut payload = vec![OK];
        payload.push(0xAA);
        assert!(decode_response(&payload).is_err());
    }

    /// 同名头出现两次,意味着有一条会被丢掉 —— 而哪条进了签名基会
    /// 直接改变签名。不在协议层替调用方挑。
    #[test]
    fn a_duplicated_header_is_refused() {
        let mut body = Encoder::default();
        body.push(0x01);
        body.string16("d").unwrap();
        body.string16("").unwrap();
        body.string16("GET").unwrap();
        body.string16("https://e.com/").unwrap();
        body.u16(2);
        body.string16("x-a").unwrap();
        body.string16("1").unwrap();
        body.string16("x-a").unwrap();
        body.string16("2").unwrap();
        body.opt_body(None).unwrap();
        body.u16(0);

        let mut payload = vec![SIGN];
        payload.extend_from_slice(body.as_slice());

        let err = decode_request(&payload).unwrap_err();
        assert!(err.to_string().contains("twice"), "{err}");
    }

    #[test]
    fn an_unknown_message_type_is_refused() {
        assert!(decode_request(&[0x7F]).is_err());
        assert!(decode_response(&[0x7F]).is_err());
        // 应答的类型码不能当请求收,反之亦然。
        assert!(decode_request(&[OK]).is_err());
        assert!(decode_response(&[LIST_KEYS]).is_err());
    }

    /// 错误码表是**故意**比内部错误粗的:错口令和错 device.secret 在密码学上
    /// 就分不出来,协议层假装能分只会给爆破的人送信息。
    #[test]
    fn the_wire_never_tells_a_caller_which_credential_was_wrong() {
        let passphrase = Response::from_error(&KeydError::BadPassphrase);
        let device_secret = Response::from_error(&KeydError::BadDeviceSecret);

        // 码一样。
        assert_eq!(passphrase, device_secret);
        assert_eq!(
            passphrase,
            Response::Error {
                code: ErrorCode::BadCredential,
                message: "the credential was refused".into(),
            }
        );

        // 而且这句话里不带任何指向性的词 —— 就算以后有人改了
        // `KeydError` 的 `Display`,这里也拦得住。
        let Response::Error { message, .. } = &passphrase else { unreachable!() };
        assert!(!message.contains("passphrase"), "{message}");
        assert!(!message.contains("device"), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }

    /// 内部故障不许把内部细节漏给对端。
    #[test]
    fn internal_failures_collapse_to_one_opaque_code() {
        for error in [
            KeydError::Crypto("the real reason".into()),
            KeydError::Upstream("the real reason".into()),
            KeydError::Json(serde_json::from_str::<u8>("x").unwrap_err()),
        ] {
            assert_eq!(error.wire_code(), ErrorCode::Internal);
        }
    }

    #[test]
    fn error_codes_round_trip_and_unknown_ones_are_refused() {
        for code in [
            ErrorCode::BadCredential,
            ErrorCode::AadMismatch,
            ErrorCode::KeyNotFound,
            ErrorCode::KeyExists,
            ErrorCode::Locked,
            ErrorCode::Permission,
            ErrorCode::RawDisabled,
            ErrorCode::CoveredSetRejected,
            ErrorCode::Protocol,
            ErrorCode::Did,
            ErrorCode::Internal,
        ] {
            assert_eq!(ErrorCode::from_u16(code.as_u16()), Some(code));
        }

        assert_eq!(ErrorCode::from_u16(0), None);
        assert_eq!(ErrorCode::from_u16(0x1234), None);
    }

    /// 超长字段发不出去,而不是被截断成半句话 —— 半句话读起来像别的东西。
    #[test]
    fn an_over_long_string_field_is_refused_rather_than_truncated() {
        let mut wire = Vec::new();
        let huge = "x".repeat(70_000);
        let err = write_response(
            &mut wire,
            &Response::Error { code: ErrorCode::Internal, message: huge },
        )
        .unwrap_err();

        assert!(err.to_string().contains("too long"), "{err}");
        assert!(wire.is_empty(), "nothing may be written when the message does not fit");
    }

    /// `round_trip` 在一对真 socket 上也得通 —— 这是客户端和守护进程
    /// 实际用的那条路径。
    #[test]
    fn round_trip_works_over_a_real_socket() {
        use std::os::unix::net::UnixStream;

        let (mut client, mut server) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let request = read_request(&mut server).unwrap().unwrap();
            assert_eq!(request, Request::Status);
            write_response(
                &mut server,
                &Response::Status(vec![UnlockedKey {
                    did: "did:wba:x".into(),
                    kid: "did:wba:x#key-1".into(),
                    unlocked_secs: 3,
                }]),
            )
            .unwrap();
        });

        let response = round_trip(&mut client, &Request::Status).unwrap();
        assert_eq!(
            response,
            Response::Status(vec![UnlockedKey {
                did: "did:wba:x".into(),
                kid: "did:wba:x#key-1".into(),
                unlocked_secs: 3,
            }])
        );
        handle.join().unwrap();
    }
}
