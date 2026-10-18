//! The setup network's DNS: every name resolves to the device, so a phone
//! that joins finds the portal whatever it looks up, and its captive-portal
//! check opens the page by itself.

const HEADER: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_ANY: u16 = 255;
/// Short, so a phone that leaves the setup network doesn't keep the answers.
const TTL: u32 = 10;

/// The reply to `query`, answering an A (or ANY) question with `ip` and any
/// other type with no records, or `None` for what isn't a single-question
/// query.
pub fn dns_answer(query: &[u8], ip: [u8; 4]) -> Option<Vec<u8>> {
    let is_response = query.get(2)? & 0x80 != 0;
    let opcode = (query[2] >> 3) & 0x0F;
    if query.len() < HEADER || is_response || opcode != 0 || u16_at(query, 4) != Some(1) {
        return None;
    }
    let mut end = HEADER;
    loop {
        let len = *query.get(end)? as usize;
        end += 1;
        if len == 0 {
            break;
        }
        // Compression pointers have the top bits set; a query never uses them.
        if len & 0xC0 != 0 {
            return None;
        }
        end += len;
    }
    let qtype = u16_at(query, end)?;
    end += 4;
    if end > query.len() {
        return None;
    }

    let answers = u16::from(qtype == TYPE_A || qtype == TYPE_ANY);
    let mut reply = Vec::with_capacity(end + 16);
    reply.extend_from_slice(&query[..2]);
    // A response, authoritative, with the query's recursion-desired bit.
    reply.extend_from_slice(&[0x84 | (query[2] & 0x01), 0x00]);
    reply.extend_from_slice(&[0, 1, 0, answers as u8, 0, 0, 0, 0]);
    reply.extend_from_slice(&query[HEADER..end]);
    if answers == 1 {
        reply.extend_from_slice(&[0xC0, HEADER as u8]); // the question's name
        reply.extend_from_slice(&TYPE_A.to_be_bytes());
        reply.extend_from_slice(&1u16.to_be_bytes()); // IN
        reply.extend_from_slice(&TTL.to_be_bytes());
        reply.extend_from_slice(&4u16.to_be_bytes());
        reply.extend_from_slice(&ip);
    }
    Some(reply)
}

fn u16_at(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(at)?, *buf.get(at + 1)?]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: [u8; 4] = [192, 168, 4, 1];

    /// A query for captive.apple.com, as a phone sends it, with an EDNS record.
    fn query(qtype: u16) -> Vec<u8> {
        let mut q = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
        for label in ["captive", "apple", "com"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        q
    }

    #[test]
    fn answers_a_with_the_device() {
        let q = query(TYPE_A);
        let r = dns_answer(&q, IP).unwrap();
        assert_eq!(&r[..12], &[0xAB, 0xCD, 0x85, 0x00, 0, 1, 0, 1, 0, 0, 0, 0]);
        let question = &q[12..q.len() - 11];
        assert_eq!(&r[12..12 + question.len()], question);
        assert_eq!(&r[12 + question.len()..], &[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 192, 168, 4, 1]);
    }

    #[test]
    fn other_types_get_no_records() {
        let r = dns_answer(&query(28), IP).unwrap();
        assert_eq!(&r[6..8], &[0, 0]);
        assert_eq!(r.len(), query(28).len() - 11);
    }

    #[test]
    fn ignores_what_isnt_a_plain_query() {
        let mut response = query(TYPE_A);
        response[2] |= 0x80;
        assert_eq!(dns_answer(&response, IP), None);
        assert_eq!(dns_answer(&query(TYPE_A)[..20], IP), None);
        assert_eq!(dns_answer(&[0; 5], IP), None);
        let mut pointer = query(TYPE_A);
        pointer[12] = 0xC0;
        assert_eq!(dns_answer(&pointer, IP), None);
    }
}
