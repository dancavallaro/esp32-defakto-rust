/// Keeps "|" out of the signing string, and keeps IDs safe as file names.
pub fn validate_device_id(id: &str) -> Result<(), String> {
    const MAX_LEN: usize = 64;
    if id.is_empty() {
        return Err("device ID is empty".into());
    }
    if id.len() > MAX_LEN {
        return Err(format!("device ID is {} characters, want at most {MAX_LEN}", id.len()));
    }
    if id == "." || id == ".." {
        return Err(format!("device ID {id:?} is reserved"));
    }
    if !id.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-')) {
        return Err(format!("device ID {id:?} may contain only lowercase letters, digits, and .-_"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_rules() {
        for ok in ["defakto-demo", "a.b_c-1", "starlord", "pennyskitchen", "hatch", "lcd-stick-esp32", "a1b2c3d4e5f6", "esp32_01", "v1.2"] {
            assert!(validate_device_id(ok).is_ok(), "{ok:?} should be accepted");
        }
        let too_long = "a".repeat(65);
        for bad in [
            "", ".", "..", "C6", "a|b", "star|lord", "star lord", "Starlord", "star/lord", "starlörd", &too_long, "star:lord",
            "star%lord",
        ] {
            assert!(validate_device_id(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
