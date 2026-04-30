use crate::models::PROTOCOL_OPENID4VP_V1_UNSIGNED;
use alloc::vec;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub const RESPONSE_MODE_DC_API: &str = "dc_api";
pub const RESPONSE_MODE_DC_API_JWT: &str = "dc_api.jwt";
pub const RESPONSE_TYPE_VP_TOKEN: &str = "vp_token";
pub const QUERY_METHOD_DCQL_QUERY: &str = "dcql_query";
pub const REQUEST_PARAMETER_TRANSACTION_DATA: &str = "transaction_data";

/// Wallet-supported OpenID4VP capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OpenId4VpConfig {
    /// Whether OpenID4VP requests are supported at all.
    pub enabled: bool,
    /// DC API protocol variants supported by this matcher.
    pub supported_request_protocols: Vec<String>,
    /// OpenID4VP response modes supported by this matcher.
    pub supported_response_modes: Vec<String>,
    /// OpenID4VP response types supported by this matcher when present.
    pub supported_response_types: Vec<String>,
    /// Query mechanisms supported by this matcher.
    pub supported_query_methods: Vec<String>,
    /// Extra request parameters supported by this matcher.
    pub supported_request_parameters: Vec<String>,
}

impl OpenId4VpConfig {
    /// Returns a configuration with all features disabled.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Returns base OpenID4VP 1.0 DC API support.
    pub fn openid4vp1() -> Self {
        Self {
            enabled: true,
            supported_request_protocols: vec![PROTOCOL_OPENID4VP_V1_UNSIGNED.to_string()],
            supported_response_modes: vec![RESPONSE_MODE_DC_API.to_string()],
            supported_response_types: vec![RESPONSE_TYPE_VP_TOKEN.to_string()],
            supported_query_methods: vec![QUERY_METHOD_DCQL_QUERY.to_string()],
            supported_request_parameters: vec![REQUEST_PARAMETER_TRANSACTION_DATA.to_string()],
        }
    }

    pub fn supports_request_protocol(&self, protocol: &str) -> bool {
        contains_capability(&self.supported_request_protocols, protocol)
    }

    pub fn supports_response_mode(&self, response_mode: &str) -> bool {
        contains_capability(&self.supported_response_modes, response_mode)
    }

    pub fn supports_response_type(&self, response_type: &str) -> bool {
        contains_capability(&self.supported_response_types, response_type)
    }

    pub fn supports_query_method(&self, query_method: &str) -> bool {
        contains_capability(&self.supported_query_methods, query_method)
    }

    pub fn supports_request_parameter(&self, parameter: &str) -> bool {
        contains_capability(&self.supported_request_parameters, parameter)
    }
}

fn contains_capability(values: &[String], value: &str) -> bool {
    values.iter().any(|candidate| candidate == value)
}
