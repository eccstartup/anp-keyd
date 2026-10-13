//! `did:wba` 的解析、URL 映射,以及文档的构造与绑定校验。

pub mod document;
pub mod parse;

pub use document::{build_unsigned, sign_document, verify_path_binding, DidDocumentSpec};
pub use parse::{did_url_path, parse_did_wba, DidWbaParts};
