//! A serial-console stand-in for the display, for boards without one. Uses
//! `println!` rather than `log` so log prefixes don't skew the QR code.

use demo::app::{Provisioning, Screen, Status};
use demo::setup::wifi_qr;
use qrcodegen::{QrCode, QrCodeEcc};

const QUIET_ZONE: i32 = 2;

pub fn render(screen: &Screen, status: &Status) {
    match screen {
        Screen::Idle => {
            println!("\n== Defakto demo ==  WiFi {}  SVID {}  {}", dot(status.wifi), dot(status.svid), status.attestor);
            println!("Press BOOT to check in.");
        }
        Screen::Starting => println!("Contacting the identity provider…"),
        Screen::Qr { uri, verification_uri, user_code, .. } => {
            print_qr(uri);
            println!("Scan, or visit {verification_uri} and enter {user_code}. Press BOOT to cancel.");
        }
        Screen::Progress(_) => println!("Checking in…"),
        Screen::Result { claims: c, checked_in } => {
            println!("\n{}{}", c.greeting, if *checked_in { "  ✓ checked in" } else { "" });
            if let Some(email) = &c.email {
                println!("  email   {email}");
            }
            println!("  user    {}", c.user_sub);
            println!("  via     {}", c.user_iss);
            println!("  actor   {}", c.actor);
            if let Some(txn) = &c.txn {
                println!("  txn     {txn}");
            }
            println!("Press BOOT to start over.");
        }
        Screen::Error(msg) => println!("\nCheck-in failed: {msg}\nPress BOOT to start over."),
        Screen::Setup { ssid, password, portal } => {
            print_qr(&wifi_qr(ssid, password));
            println!("Set up this device: scan, or join {ssid} with password {password}, then open {portal}.");
        }
        Screen::Restarting => println!("Saved. Restarting…"),
        Screen::Provisioning(Provisioning::Checking) => println!("Checking the DevID that came with the new settings…"),
        Screen::Provisioning(Provisioning::Configured(developer)) => println!("Set up by {developer}. Restarting…"),
        Screen::Provisioning(Provisioning::Refused(why)) => println!("Settings refused: {why}. Restarting…"),
    }
}

fn dot(ok: bool) -> &'static str {
    if ok { "●" } else { "○" }
}

/// Two modules per character cell. Light modules are drawn, so the code reads
/// correctly on a dark terminal.
fn print_qr(text: &str) {
    let Ok(qr) = QrCode::encode_text(text, QrCodeEcc::Low) else {
        println!("(URL too long for a QR code)");
        return;
    };
    let light = |x: i32, y: i32| !qr.get_module(x, y);
    let (lo, hi) = (-QUIET_ZONE, qr.size() + QUIET_ZONE);
    for y in (lo..hi).step_by(2) {
        let row: String = (lo..hi)
            .map(|x| match (light(x, y), y + 1 < hi && light(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            })
            .collect();
        println!("{row}");
    }
}
