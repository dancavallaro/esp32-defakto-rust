//! The setup wizard: the settings its portal edits, how they're checked and
//! stored, and the page that edits them. The firmware serves the page from its
//! own access point, so a device needs nothing configured before it's flashed.

use std::collections::BTreeMap;
use std::fmt::Write;

use defakto::http::HttpClient;
use defakto::jwt;
use defakto::verify::{self, Expected};

use crate::flow;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    Text,
    Password,
    Url,
    /// Checkboxes, kept as the chosen values joined with commas.
    Choices(&'static [(&'static str, &'static str)]),
}

/// The attestation methods, as the firmware names them and as the page does.
pub const ATTESTORS: &[(&str, &str)] = &[("efuse", "eFuse HMAC"), ("tee", "ESP-TEE")];

pub struct Field {
    pub key: &'static str,
    pub section: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    pub kind: Kind,
    pub required: bool,
    /// Shown folded away, since the defaults suit every IdP so far.
    pub advanced: bool,
}

const fn field(key: &'static str, section: &'static str, label: &'static str, help: &'static str, kind: Kind) -> Field {
    Field { key, section, label, help, kind, required: true, advanced: false }
}

pub const FIELDS: &[Field] = &[
    field("wifi_ssid", "WiFi", "Network", "", Kind::Text),
    Field { required: false, ..field("wifi_psk", "WiFi", "Password", "Blank for an open network.", Kind::Password) },
    field("login_device_url", "Sign-in", "Device authorization endpoint", "From the IdP's OIDC discovery document.", Kind::Url),
    field("login_token_url", "Sign-in", "Token endpoint", "From the same discovery document.", Kind::Url),
    field("login_client_id", "Sign-in", "Client ID", "", Kind::Text),
    field("svid_audience", "Defakto", "Trust domain issuer", "The iss of the trust domain's JWT-SVIDs.", Kind::Url),
    field("device_id", "Defakto", "Device ID", "As enrolled with the attestor.", Kind::Text),
    field(
        "attestors",
        "Defakto",
        "Attestation methods",
        "A long press on the idle screen switches between those enabled.",
        Kind::Choices(ATTESTORS),
    ),
    field("obo_audience", "Defakto", "OBO audience", "Who the OBO token is for.", Kind::Text),
    Field { advanced: true, ..field("subject_token_type", "Defakto", "Subject token type", "", Kind::Text) },
    Field { advanced: true, ..field("requested_token_type", "Defakto", "Requested token type", "", Kind::Text) },
    Field {
        required: false,
        ..field("checkin_url", "Check-in", "Check-in endpoint", "Blank to stop at the token exchange.", Kind::Url)
    },
];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Settings {
    pub wifi_ssid: String,
    pub wifi_psk: String,
    pub login_device_url: String,
    pub login_token_url: String,
    pub login_client_id: String,
    pub svid_audience: String,
    pub device_id: String,
    /// The attestation methods enabled, such as `efuse,tee`.
    pub attestors: String,
    pub obo_audience: String,
    pub subject_token_type: String,
    pub requested_token_type: String,
    /// Empty for none.
    pub checkin_url: String,
}

impl Settings {
    pub fn get(&self, key: &str) -> Option<&str> {
        Some(match key {
            "wifi_ssid" => &self.wifi_ssid,
            "wifi_psk" => &self.wifi_psk,
            "login_device_url" => &self.login_device_url,
            "login_token_url" => &self.login_token_url,
            "login_client_id" => &self.login_client_id,
            "svid_audience" => &self.svid_audience,
            "device_id" => &self.device_id,
            "attestors" => &self.attestors,
            "obo_audience" => &self.obo_audience,
            "subject_token_type" => &self.subject_token_type,
            "requested_token_type" => &self.requested_token_type,
            "checkin_url" => &self.checkin_url,
            _ => return None,
        })
    }

    fn slot(&mut self, key: &str) -> Option<&mut String> {
        Some(match key {
            "wifi_ssid" => &mut self.wifi_ssid,
            "wifi_psk" => &mut self.wifi_psk,
            "login_device_url" => &mut self.login_device_url,
            "login_token_url" => &mut self.login_token_url,
            "login_client_id" => &mut self.login_client_id,
            "svid_audience" => &mut self.svid_audience,
            "device_id" => &mut self.device_id,
            "attestors" => &mut self.attestors,
            "obo_audience" => &mut self.obo_audience,
            "subject_token_type" => &mut self.subject_token_type,
            "requested_token_type" => &mut self.requested_token_type,
            "checkin_url" => &mut self.checkin_url,
            _ => return None,
        })
    }

    /// How the settings are kept in NVS: the same encoding the form posts.
    pub fn to_form(&self) -> String {
        let mut form = form_urlencoded::Serializer::new(String::new());
        for f in FIELDS {
            form.append_pair(f.key, self.get(f.key).unwrap_or_default());
        }
        form.finish()
    }

    /// These settings with any fields `form` names replaced. Unknown keys are
    /// ignored, so settings saved by a newer build still load. A choices field
    /// collects every value posted for it, and drops values it doesn't offer.
    pub fn overlaid(&self, form: &str) -> Settings {
        let mut out = self.clone();
        let mut chosen: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
        for (key, value) in form_urlencoded::parse(form.as_bytes()) {
            if let Some(f) = FIELDS.iter().find(|f| f.key == key && matches!(f.kind, Kind::Choices(_))) {
                chosen.entry(f.key).or_default().extend(value.split(',').map(|v| v.trim().to_owned()));
            } else if let Some(slot) = out.slot(&key) {
                // A WiFi password may begin or end with a space.
                *slot = if key == "wifi_psk" { value.into_owned() } else { value.trim().to_owned() };
            }
        }
        for f in FIELDS {
            if let (Kind::Choices(choices), Some(values)) = (f.kind, chosen.get(f.key)) {
                let kept: Vec<&str> = choices.iter().map(|(v, _)| *v).filter(|v| values.iter().any(|c| c == v)).collect();
                *out.slot(f.key).expect("every field has a slot") = kept.join(",");
            }
        }
        out
    }

    /// These settings with every field `build` sets replaced, so a newly
    /// flashed build's settings win and the wizard's fill in what it leaves empty.
    pub fn rebuilt(&self, build: &Settings) -> Settings {
        let mut out = self.clone();
        for f in FIELDS {
            let value = build.get(f.key).unwrap_or_default();
            if !value.is_empty() {
                *out.slot(f.key).expect("every field has a slot") = value.to_owned();
            }
        }
        out
    }

    /// The attestation methods enabled, in `ATTESTORS` order.
    pub fn enabled_attestors(&self) -> Vec<&'static str> {
        ATTESTORS.iter().map(|(v, _)| *v).filter(|v| self.attestors.split(',').any(|a| a.trim() == *v)).collect()
    }

    /// What the portal's form makes of these settings, or why it can't be
    /// saved. The password field starts blank, so a blank one keeps the saved
    /// password unless the network changed too.
    pub fn submit(&self, form: &str) -> Result<Settings, String> {
        let mut next = self.overlaid(form);
        if next.wifi_psk.is_empty() && next.wifi_ssid == self.wifi_ssid {
            next.wifi_psk.clone_from(&self.wifi_psk);
        }
        next.validate()?;
        Ok(next)
    }

    /// Whether the device can run the demo with these, or the first reason it can't.
    pub fn validate(&self) -> Result<(), String> {
        for f in FIELDS {
            let value = self.get(f.key).unwrap_or_default();
            if let Kind::Choices(choices) = f.kind {
                let mut values = value.split(',').filter(|v| !v.is_empty());
                if let Some(other) = values.find(|v| !choices.iter().any(|(c, _)| c == v)) {
                    return Err(format!("{other:?} isn't one of the {}.", f.label.to_lowercase()));
                }
            }
            if value.is_empty() {
                if f.required {
                    return Err(match f.kind {
                        Kind::Choices(_) => format!("Choose at least one of the {}.", f.label.to_lowercase()),
                        _ => format!("{} is required.", f.label),
                    });
                }
                continue;
            }
            if f.kind == Kind::Url && !(value.starts_with("https://") || value.starts_with("http://")) {
                return Err(format!("{} must be an http(s) URL.", f.label));
            }
        }
        if self.wifi_ssid.len() > 32 {
            return Err("The network name is over 32 bytes.".into());
        }
        if !self.wifi_psk.is_empty() && !(8..=63).contains(&self.wifi_psk.len()) {
            return Err("A WiFi password has 8 to 63 characters.".into());
        }
        Ok(())
    }

    pub fn flow_config(&self) -> flow::Config {
        flow::Config {
            serverless_url: flow::SERVERLESS_URL.into(),
            token_url: flow::TOKEN_URL.into(),
            svid_audience: self.svid_audience.clone(),
            login_device_url: self.login_device_url.clone(),
            login_token_url: self.login_token_url.clone(),
            login_client_id: self.login_client_id.clone(),
            subject_token_type: self.subject_token_type.clone(),
            requested_token_type: self.requested_token_type.clone(),
            obo_audience: self.obo_audience.clone(),
            checkin_url: Some(self.checkin_url.clone()).filter(|url| !url.is_empty()),
        }
    }
}

/// The form field carrying the DevID JWT-SVID, when DevID guards the portal.
pub const DEVID_FIELD: &str = "devid";

/// Who may save settings when DevID guards the portal: users whose DevID
/// JWT-SVIDs `issuer` signs, with SPIFFE IDs under `subjects`. Their token's
/// audience is the device ID being saved, so it's bound to that device.
#[derive(Debug, Clone, PartialEq)]
pub struct DevIdGate {
    pub issuer: String,
    /// A SPIFFE ID prefix, such as `spiffe://example.org/users/`.
    pub subjects: String,
}

impl DevIdGate {
    pub fn trust_domain(&self) -> &str {
        let rest = self.subjects.strip_prefix("spiffe://").unwrap_or(&self.subjects);
        rest.split('/').next().unwrap_or_default()
    }

    /// The token in `form`, if it looks right for `audience`. Its signature is
    /// checked once the device is online; this catches a wrong token first.
    pub fn precheck(&self, form: &str, audience: &str) -> Result<String, String> {
        let token = form_urlencoded::parse(form.as_bytes())
            .find(|(k, _)| k == DEVID_FIELD)
            .map(|(_, v)| v.trim().to_owned())
            .filter(|t| !t.is_empty())
            .ok_or("Paste a DevID JWT-SVID.")?;
        let claims = jwt::decode_claims(&token).map_err(|_| "That isn't a JWT.")?;
        let audiences = match &claims["aud"] {
            serde_json::Value::Array(auds) => auds.iter().filter_map(|a| a.as_str()).collect(),
            aud => aud.as_str().into_iter().collect::<Vec<_>>(),
        };
        if !audiences.contains(&audience) {
            return Err(format!("The DevID's audience is {audiences:?}; fetch one for {audience:?}."));
        }
        self.allows(claims["sub"].as_str().unwrap_or_default())?;
        Ok(token)
    }

    /// Verifies `token` against the trust domain's keys, returning the
    /// user's SPIFFE ID.
    pub fn check(&self, http: &mut impl HttpClient, token: &str, audience: &str, now: i64) -> Result<String, String> {
        let keys = verify::fetch_jwks(http, &self.issuer).map_err(|e| format!("fetching keys: {e}"))?;
        let expected = Expected { issuer: &self.issuer, audience, now };
        let verified = verify::verify_jwt_svid(token, &keys, &expected).map_err(|e| format!("DevID {e}"))?;
        self.allows(&verified.subject)?;
        Ok(verified.subject)
    }

    fn allows(&self, subject: &str) -> Result<(), String> {
        if subject.starts_with(&self.subjects) {
            Ok(())
        } else {
            Err(format!("{subject} can't set up this device."))
        }
    }
}

/// Settings waiting for their DevID to be verified, with the token, as kept in NVS.
pub fn pending_form(settings: &Settings, token: &str) -> String {
    let mut form = form_urlencoded::Serializer::new(settings.to_form());
    form.append_pair(DEVID_FIELD, token);
    form.finish()
}

/// The token in a `pending_form`; `Settings::overlaid` reads the rest.
pub fn pending_token(form: &str) -> Option<String> {
    form_urlencoded::parse(form.as_bytes()).find(|(k, _)| k == DEVID_FIELD).map(|(_, v)| v.into_owned())
}

/// The text of a QR code that joins a phone to the network, as iOS and
/// Android cameras read it.
pub fn wifi_qr(ssid: &str, psk: &str) -> String {
    format!("WIFI:T:WPA;S:{};P:{};;", wifi_escape(ssid), wifi_escape(psk))
}

fn wifi_escape(s: &str) -> String {
    s.chars().fold(String::new(), |mut out, c| {
        if matches!(c, '\\' | ';' | ',' | ':' | '"') {
            out.push('\\');
        }
        out.push(c);
        out
    })
}

/// No 0/o, 1/l/i, so the password can be typed off the screen.
const PASSWORD_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

/// The setup network's password, one character per random byte.
pub fn ap_password(random: &[u8]) -> String {
    random.iter().map(|b| PASSWORD_ALPHABET[*b as usize % PASSWORD_ALPHABET.len()] as char).collect()
}

const STYLE: &str = "body{font:16px system-ui,sans-serif;background:#0c0816;color:#e9e4f5;margin:0 auto;\
max-width:32rem;padding:1rem}h1{font-size:1.4rem}h2{font-size:1rem;color:#a07cff;margin:1.5rem 0 .5rem}\
label,legend{display:block;margin:.75rem 0 .25rem;padding:0}fieldset{border:0;margin:0;padding:0}\
.check{display:flex;align-items:center;gap:.5rem;margin:.4rem 0}.check input{width:auto;margin:0}input{box-sizing:border-box;width:100%;padding:.6rem;\
font:inherit;border:1px solid #2a2140;border-radius:6px;background:#160f26;color:inherit}\
small{color:#7d7690}code{word-break:break-all;color:#e9e4f5}textarea{box-sizing:border-box;width:100%;\
padding:.6rem;font:12px ui-monospace,monospace;border:1px solid #2a2140;border-radius:6px;background:#160f26;\
color:inherit}summary{margin-top:1rem;color:#7d7690}.err{background:#4a2a10;color:#ffcf5c;\
padding:.75rem;border-radius:6px}button{margin-top:1.5rem;width:100%;padding:.8rem;font:inherit;\
font-weight:600;border:0;border-radius:6px;background:#a07cff;color:#0c0816}";

/// The portal's form, filled in from `current`. `networks` are offered for
/// the WiFi network, `error` is why the last submission was refused, and
/// `gate` asks for a DevID.
pub fn page(current: &Settings, networks: &[String], error: Option<&str>, gate: Option<&DevIdGate>) -> String {
    let mut html = head("Set up");
    html.push_str("<h1>Set up this device</h1>");
    if let Some(error) = error {
        let _ = write!(html, "<p class=err>{}</p>", escape(error));
    }
    html.push_str("<form method=post action=/>");
    let mut section = "";
    let mut folded = false;
    for f in FIELDS {
        if f.advanced && !folded {
            html.push_str("<details><summary>Advanced</summary>");
            folded = true;
        } else if !f.advanced && folded {
            html.push_str("</details>");
            folded = false;
        }
        if f.section != section {
            let _ = write!(html, "<h2>{}</h2>", f.section);
            section = f.section;
        }
        input(&mut html, f, current);
    }
    if folded {
        html.push_str("</details>");
    }
    if let Some(gate) = gate {
        devid_input(&mut html, gate, &current.device_id);
    }
    html.push_str("<datalist id=networks>");
    for n in networks {
        let _ = write!(html, "<option value=\"{}\">", escape(n));
    }
    html.push_str("</datalist><button>Save and restart</button></form></body></html>");
    html
}

fn input(html: &mut String, f: &Field, current: &Settings) {
    let value = current.get(f.key).unwrap_or_default();
    if let Kind::Choices(choices) = f.kind {
        return checkboxes(html, f, choices, value);
    }
    let (kind, value, extra) = match f.kind {
        // Never sent back: anyone who reaches the portal would read it.
        Kind::Password => ("password", "", if value.is_empty() { "" } else { " placeholder=\"unchanged\"" }),
        Kind::Url => ("url", value, ""),
        Kind::Text if f.key == "wifi_ssid" => ("text", value, " list=networks"),
        Kind::Text => ("text", value, ""),
        Kind::Choices(_) => unreachable!("drawn as checkboxes"),
    };
    let required = if f.required { " required" } else { "" };
    let _ = write!(
        html,
        "<label for={key}>{label}</label><input id={key} name={key} type={kind} value=\"{value}\" \
         autocapitalize=off autocorrect=off spellcheck=false{extra}{required}>",
        key = f.key,
        label = f.label,
        value = escape(value),
    );
    if !f.help.is_empty() {
        let _ = write!(html, "<small>{}</small>", f.help);
    }
}

/// The empty hidden value posts the field even with every box unticked, so
/// unticking them all clears it rather than leaving it unchanged.
fn checkboxes(html: &mut String, f: &Field, choices: &[(&str, &str)], value: &str) {
    let _ = write!(html, "<fieldset><legend>{}</legend><input type=hidden name={} value=\"\">", f.label, f.key);
    for (choice, label) in choices {
        let checked = if value.split(',').any(|v| v == *choice) { " checked" } else { "" };
        let _ = write!(
            html,
            "<label class=check><input type=checkbox name={} value={choice}{checked}>{label}</label>",
            f.key
        );
    }
    html.push_str("</fieldset>");
    if !f.help.is_empty() {
        let _ = write!(html, "<small>{}</small>", f.help);
    }
}

fn devid_input(html: &mut String, gate: &DevIdGate, device_id: &str) {
    let td = escape(gate.trust_domain());
    let _ = write!(
        html,
        "<h2>DevID</h2><label for={DEVID_FIELD}>DevID JWT-SVID</label>\
         <textarea id={DEVID_FIELD} name={DEVID_FIELD} rows=5 required autocapitalize=off autocorrect=off \
         spellcheck=false></textarea><small>Only users in {td} can set up this device. On your laptop, run \
         <code>defakto dev-id fetch jwt-svid --trust-domain {td} --audience {aud}</code> (the device ID above) \
         and paste <code>~/.defakto/dev-id/{td}/svids/jwt-svid</code> here.</small>",
        aud = escape(device_id),
    );
}

/// What the portal shows once the settings are saved. With `checking`, the
/// device verifies a DevID before it uses them.
pub fn saved_page(checking: bool) -> String {
    let next = if checking {
        "The device is restarting. It joins the network, checks your DevID, and shows whether it took the settings."
    } else {
        "The device is restarting with the new settings."
    };
    head("Saved") + "<h1>Saved</h1><p>" + next + " You can leave this network.</p></body></html>"
}

fn head(title: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=utf-8>\
         <meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>{title}</title><style>{STYLE}</style></head><body>"
    )
}

fn escape(s: &str) -> String {
    s.chars().fold(String::new(), |mut out, c| {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> Settings {
        Settings {
            wifi_ssid: "home".into(),
            wifi_psk: "hunter22".into(),
            login_device_url: "https://idp/device".into(),
            login_token_url: "https://idp/token".into(),
            login_client_id: "client".into(),
            svid_audience: "https://td".into(),
            device_id: "defakto-demo".into(),
            attestors: "efuse,tee".into(),
            obo_audience: "defakto-demo".into(),
            subject_token_type: "urn:ietf:params:oauth:token-type:id_token".into(),
            requested_token_type: "urn:defakto:security:token-type:jwt-svid-obo".into(),
            checkin_url: String::new(),
        }
    }

    #[test]
    fn every_field_has_a_slot() {
        let mut s = Settings::default();
        for f in FIELDS {
            assert!(s.slot(f.key).is_some(), "{}", f.key);
        }
    }

    #[test]
    fn stored_form_round_trips() {
        let s = Settings { checkin_url: "https://checkin/x?a=b&c=d".into(), wifi_psk: " a;b=c& ".into(), ..complete() };
        assert_eq!(Settings::default().overlaid(&s.to_form()), s);
    }

    #[test]
    fn overlay_keeps_unnamed_fields_and_ignores_unknown_keys() {
        let s = complete().overlaid("login_client_id=+other+&from_the_future=1");
        assert_eq!(s, Settings { login_client_id: "other".into(), ..complete() });
    }

    #[test]
    fn a_new_build_replaces_what_it_sets_and_keeps_the_rest() {
        let build = Settings { login_token_url: "https://auth0/token".into(), attestors: "efuse,tee".into(), ..Default::default() };
        let saved = Settings { attestors: "tee".into(), ..complete() };
        let s = saved.rebuilt(&build);
        assert_eq!(s, Settings { login_token_url: "https://auth0/token".into(), ..complete() });
    }

    #[test]
    fn blank_password_keeps_the_saved_one_on_the_same_network() {
        let s = complete().submit("wifi_ssid=home&wifi_psk=").unwrap();
        assert_eq!(s.wifi_psk, "hunter22");
    }

    #[test]
    fn blank_password_on_a_new_network_means_open() {
        let s = complete().submit("wifi_ssid=cafe&wifi_psk=").unwrap();
        assert_eq!((s.wifi_ssid.as_str(), s.wifi_psk.as_str()), ("cafe", ""));
    }

    #[test]
    fn submit_refuses_what_validate_refuses() {
        assert_eq!(complete().submit("login_client_id=").unwrap_err(), "Client ID is required.");
        assert_eq!(complete().submit("checkin_url=checkin.local").unwrap_err(), "Check-in endpoint must be an http(s) URL.");
        assert_eq!(complete().submit("wifi_psk=short").unwrap_err(), "A WiFi password has 8 to 63 characters.");
    }

    #[test]
    fn optional_fields_may_be_blank() {
        assert_eq!(Settings { wifi_psk: String::new(), ..complete() }.validate(), Ok(()));
        assert_eq!(complete().flow_config().checkin_url, None);
        let s = Settings { checkin_url: "https://c/checkin".into(), ..complete() };
        assert_eq!(s.flow_config().checkin_url.as_deref(), Some("https://c/checkin"));
    }

    #[test]
    fn defaults_alone_are_incomplete() {
        assert!(Settings::default().validate().is_err());
    }

    #[test]
    fn attestors_follow_the_ticked_boxes() {
        let only_tee = complete().submit("attestors=&attestors=tee").unwrap();
        assert_eq!(only_tee.attestors, "tee");
        assert_eq!(only_tee.enabled_attestors(), ["tee"]);
        let both = only_tee.submit("attestors=&attestors=tee&attestors=efuse&attestors=nvs").unwrap();
        assert_eq!(both.attestors, "efuse,tee", "in ATTESTORS order, without unknown values");
        assert_eq!(complete().submit("login_client_id=x").unwrap().attestors, "efuse,tee", "unchanged when not posted");
        assert_eq!(complete().submit("attestors=").unwrap_err(), "Choose at least one of the attestation methods.");
    }

    #[test]
    fn stored_attestors_round_trip() {
        let s = Settings { attestors: "tee".into(), ..complete() };
        assert_eq!(Settings::default().overlaid(&s.to_form()), s);
    }

    #[test]
    fn attestors_from_the_build_must_be_known() {
        let s = Settings { attestors: "efuse,hsm".into(), ..complete() };
        assert_eq!(s.validate(), Err("\"hsm\" isn't one of the attestation methods.".into()));
        assert_eq!(s.enabled_attestors(), ["efuse"]);
    }

    #[test]
    fn page_ticks_the_enabled_attestors() {
        let html = page(&Settings { attestors: "tee".into(), ..complete() }, &[], None, None);
        assert!(html.contains("<input type=hidden name=attestors value=\"\">"));
        assert!(html.contains("value=efuse>eFuse HMAC"));
        assert!(html.contains("value=tee checked>ESP-TEE"));
    }

    #[test]
    fn wifi_qr_escapes_its_delimiters() {
        assert_eq!(wifi_qr("a;b", r#"p:w,"\"#), r#"WIFI:T:WPA;S:a\;b;P:p\:w\,\"\\;;"#);
    }

    #[test]
    fn ap_password_avoids_lookalikes() {
        let pw = ap_password(&[0, 1, 30, 31]);
        assert_eq!(pw, "ab9a");
        assert!(!ap_password(&(0..=255).collect::<Vec<u8>>()).contains(['0', 'o', '1', 'l', 'i']));
    }

    #[test]
    fn page_escapes_values_and_hides_the_password() {
        let s = Settings { login_client_id: "\"><script>".into(), ..complete() };
        let html = page(&s, &["<net>".into()], Some("bad & worse"), None);
        assert!(html.contains("value=\"&quot;&gt;&lt;script&gt;\""));
        assert!(html.contains("<option value=\"&lt;net&gt;\">"));
        assert!(html.contains("<p class=err>bad &amp; worse</p>"));
        assert!(!html.contains("hunter22"));
        assert!(html.contains("placeholder=\"unchanged\""));
    }

    #[test]
    fn page_posts_every_field() {
        let html = page(&complete(), &[], None, None);
        for f in FIELDS {
            assert!(html.contains(&format!(" name={} ", f.key)), "{}", f.key);
        }
        assert_eq!(html.matches("<details>").count(), html.matches("</details>").count());
        assert!(!html.contains("name=devid"));
    }

    fn gate() -> DevIdGate {
        DevIdGate { issuer: "https://td.example/t-1".into(), subjects: "spiffe://td.example/users/".into() }
    }

    fn devid(aud: serde_json::Value, sub: &str) -> String {
        defakto::testing::make_jwt(&serde_json::json!({"aud": aud, "sub": sub}))
    }

    #[test]
    fn page_asks_for_a_devid_for_this_device() {
        let html = page(&complete(), &[], None, Some(&gate()));
        assert!(html.contains("name=devid"));
        assert!(html.contains("--trust-domain td.example --audience defakto-demo"));
    }

    #[test]
    fn precheck_catches_the_wrong_token() {
        let form = |token: &str| format!("devid={token}");
        let alice = devid("defakto-demo".into(), "spiffe://td.example/users/alice");
        assert_eq!(gate().precheck(&form(&alice), "defakto-demo"), Ok(alice.clone()));
        let listed = devid(serde_json::json!(["x", "defakto-demo"]), "spiffe://td.example/users/alice");
        assert!(gate().precheck(&form(&listed), "defakto-demo").is_ok());

        assert_eq!(gate().precheck("devid=+", "defakto-demo"), Err("Paste a DevID JWT-SVID.".into()));
        assert_eq!(gate().precheck(&form("nope"), "defakto-demo"), Err("That isn't a JWT.".into()));
        let other_aud = devid("testing123".into(), "spiffe://td.example/users/alice");
        assert!(gate().precheck(&form(&other_aud), "defakto-demo").unwrap_err().contains("testing123"));
        let workload = devid("defakto-demo".into(), "spiffe://td.example/iot/defakto-demo");
        assert_eq!(
            gate().precheck(&form(&workload), "defakto-demo"),
            Err("spiffe://td.example/iot/defakto-demo can't set up this device.".into())
        );
    }

    #[test]
    fn pending_keeps_settings_and_token_apart() {
        let form = pending_form(&complete(), "a.b.c");
        assert_eq!(Settings::default().overlaid(&form), complete());
        assert_eq!(pending_token(&form).as_deref(), Some("a.b.c"));
        assert_eq!(pending_token(&complete().to_form()), None);
    }

    #[test]
    fn check_says_what_failed() {
        // `defakto::verify` tests the signature check itself.
        let mut http = defakto::testing::FakeHttp::default().fail("unreachable");
        assert_eq!(gate().check(&mut http, "t", "defakto-demo", 0), Err("fetching keys: network: unreachable".into()));
    }
}
