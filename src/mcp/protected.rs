//! Protected v2 MCP. Endpoint and trust root are fixed at process startup.
use crate::security::{client::Client, protocol::DataRequest};
use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::schemars;
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler, ServiceExt};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Keyd {
    config: PathBuf,
    tool_router: ToolRouter<Self>,
}
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantArgs {
    pub grant_id: String,
}
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocumentArgs {
    pub key_id: String,
}
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestArgs {
    pub request_id: String,
}
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignArgs {
    pub grant_id: String,
    pub request_id: String,
    pub http: crate::security::http::HttpRequest,
}
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}
#[tool_router]
impl Keyd {
    pub fn new(config: PathBuf) -> Self {
        Self {
            config,
            tool_router: Self::tool_router(),
        }
    }
    async fn call(&self, request: DataRequest) -> Result<CallToolResult, ErrorData> {
        let config = self.config.clone();
        let reply =
            tokio::task::spawn_blocking(move || Client::connect(&config, false)?.data(request))
                .await
                .map_err(|_| ErrorData::internal_error("protected request task failed", None))?
                .map_err(super::refusal)?;
        let text = serde_json::to_string(&reply)
            .map_err(|_| ErrorData::internal_error("result encoding failed", None))?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }
    #[tool(description = "List only exact hot keys with current grants for this OS principal")]
    async fn list_my_keys(
        &self,
        Parameters(_): Parameters<NoArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.call(DataRequest::ListAuthorizedKeys {}).await
    }
    #[tool(description = "Read this principal's grant state and remaining limits")]
    async fn grant_status(
        &self,
        Parameters(a): Parameters<GrantArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.call(DataRequest::GrantStatus {
            grant_id: a.grant_id,
        })
        .await
    }
    #[tool(description = "Get the public document for an authorized key handle")]
    async fn get_did_document(
        &self,
        Parameters(a): Parameters<DocumentArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.call(DataRequest::Document { key_id: a.key_id }).await
    }
    #[tool(
        description = "Submit one structured HTTP request with an existing grant and stable request UUID; no automatic retry. Signing remains unavailable until the transactional executor is enabled"
    )]
    async fn sign_request(
        &self,
        Parameters(a): Parameters<SignArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.call(DataRequest::SignHttp {
            grant_id: a.grant_id,
            request_id: a.request_id,
            http: a.http,
        })
        .await
    }
    #[tool(
        description = "Query a request UUID owned by this principal; never resubmits a signature"
    )]
    async fn request_status(
        &self,
        Parameters(a): Parameters<RequestArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.call(DataRequest::RequestStatus {
            request_id: a.request_id,
        })
        .await
    }
}
#[tool_handler]
impl ServerHandler for Keyd {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {capabilities:ServerCapabilities::builder().enable_tools().build(),instructions:Some("Protected v2 only. No passwords, unlock, raw/challenge signatures or endpoint overrides. M4 transaction signing is not enabled.".into()),..Default::default()}
    }
}
pub fn serve(config: PathBuf) -> crate::error::Result<()> {
    crate::security::require_boundary_platform()?;
    crate::security::config::ServiceConfig::load(&config)?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let service = Keyd::new(config)
                .serve(rmcp::transport::stdio())
                .await
                .map_err(|_| crate::error::KeydError::Protocol("MCP handshake failed".into()))?;
            service
                .waiting()
                .await
                .map_err(|_| crate::error::KeydError::Protocol("MCP stopped".into()))?;
            Ok(())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protected_tools_have_no_identity_endpoint_or_secret_overrides() {
        let tools = Keyd::tool_router().list_all();
        assert_eq!(tools.len(), 5);
        for tool in tools {
            let schema = serde_json::to_string(&tool.input_schema).unwrap();
            for name in [
                "passphrase",
                "password",
                "socket",
                "config",
                "root",
                "did",
                "kid",
                "covered",
            ] {
                assert!(
                    !schema.contains(&format!("\"{name}\"")),
                    "{} contains {name}",
                    tool.name
                );
            }
        }
        assert!(
            serde_json::from_value::<NoArgs>(serde_json::json!({"socket":"/tmp/evil"})).is_err()
        );
        assert!(serde_json::from_value::<GrantArgs>(
            serde_json::json!({"grant_id":"x","root":"/tmp/evil"})
        )
        .is_err());
    }
}
