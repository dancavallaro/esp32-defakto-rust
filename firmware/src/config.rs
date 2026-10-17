//! Build-time settings from `cfg.toml`; see `cfg.toml.example`.

#[toml_cfg::toml_config]
pub struct Config {
    #[default("")]
    wifi_ssid: &'static str,
    #[default("")]
    wifi_psk: &'static str,
    #[default("defakto-demo")]
    device_id: &'static str,
    #[default("")]
    login_device_url: &'static str,
    #[default("")]
    login_token_url: &'static str,
    #[default("")]
    login_client_id: &'static str,
    #[default("")]
    svid_audience: &'static str,
    #[default("urn:ietf:params:oauth:token-type:id_token")]
    subject_token_type: &'static str,
    #[default("urn:defakto:security:token-type:jwt-svid-obo")]
    requested_token_type: &'static str,
    #[default("defakto-demo")]
    obo_audience: &'static str,
    #[default("efuse")]
    default_attestor: &'static str,
    /// The eFuse key block (0 to 5) holding the device secret for `efuse`.
    #[default(5)]
    efuse_hmac_key: u8,
}

pub fn flow_config() -> demo::flow::Config {
    demo::flow::Config {
        serverless_url: demo::flow::SERVERLESS_URL.into(),
        token_url: demo::flow::TOKEN_URL.into(),
        svid_audience: CONFIG.svid_audience.into(),
        login_device_url: CONFIG.login_device_url.into(),
        login_token_url: CONFIG.login_token_url.into(),
        login_client_id: CONFIG.login_client_id.into(),
        subject_token_type: CONFIG.subject_token_type.into(),
        requested_token_type: CONFIG.requested_token_type.into(),
        obo_audience: CONFIG.obo_audience.into(),
    }
}
