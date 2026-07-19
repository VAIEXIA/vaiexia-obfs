//! Inner datagram framing: [type u8][body]

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DgramType {
    Hs1 = 0x01,
    Hs2 = 0x02,
    Hs3 = 0x03,
    Cookie = 0x04,
    Data = 0x05,
}

impl DgramType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(DgramType::Hs1),
            0x02 => Some(DgramType::Hs2),
            0x03 => Some(DgramType::Hs3),
            0x04 => Some(DgramType::Cookie),
            0x05 => Some(DgramType::Data),
            _ => None,
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Encode a type-tagged inner datagram: [type_byte][body]
pub fn encode_inner(ty: DgramType, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(ty.as_byte());
    out.extend_from_slice(body);
    out
}

/// Decode a type-tagged inner datagram. Returns None on empty or unknown type.
pub fn decode_inner(data: &[u8]) -> Option<(DgramType, &[u8])> {
    if data.is_empty() {
        return None;
    }
    let ty = DgramType::from_byte(data[0])?;
    Some((ty, &data[1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_types() {
        for ty in [DgramType::Hs1, DgramType::Hs2, DgramType::Hs3, DgramType::Cookie, DgramType::Data] {
            let body = b"test body data";
            let encoded = encode_inner(ty, body);
            let (got_ty, got_body) = decode_inner(&encoded).expect("should decode");
            assert_eq!(got_ty, ty);
            assert_eq!(got_body, body);
        }
    }

    #[test]
    fn unknown_type_returns_none() {
        let data = [0xFF, 0x01, 0x02];
        assert_eq!(decode_inner(&data), None);
    }

    #[test]
    fn empty_input_returns_none() {
        assert_eq!(decode_inner(&[]), None);
    }

    #[test]
    fn empty_body_roundtrips() {
        let encoded = encode_inner(DgramType::Data, &[]);
        let (ty, body) = decode_inner(&encoded).unwrap();
        assert_eq!(ty, DgramType::Data);
        assert_eq!(body, &[] as &[u8]);
    }
}
