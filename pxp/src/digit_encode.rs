const CHUNK_SIZE: usize = 7;
const CHUNK_DIGITS: usize = 17;
const ZEROS: &str = "00000000000000000";

/// The number of digits needed to encode each length of trailing data from 6 bytes down to zero,
/// i.e. it’s 15, 13, 10, 8, 5, 3, 0 written in hex.
const PARTIAL_CHUNK_DIGITS: usize = 0x0fda8530;

pub fn digit_encode(input: &[u8]) -> String {
    let mut output = String::new();
    for chunk_slice in input.chunks(CHUNK_SIZE) {
        let mut chunk = [0u8; 8];
        let (head, _) = chunk.split_at_mut(chunk_slice.len());
        head.copy_from_slice(chunk_slice);
        let v = u64::from_le_bytes(chunk);
        let v = v.to_string();
        let digits = if chunk_slice.len() == CHUNK_SIZE {
            CHUNK_DIGITS
        } else {
            0x0F & (PARTIAL_CHUNK_DIGITS >> (4 * chunk_slice.len()))
        };
        // ZEROS is 17 chars (CHUNK_DIGITS); slice within bounds.
        let pad_len = digits.saturating_sub(v.len());
        if let Some(pad) = ZEROS.get(..pad_len) {
            output.push_str(pad);
        }
        output.push_str(&v);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::digit_encode;

    #[test]
    fn test_digit_encode() {
        assert_eq!(digit_encode(b"hello world"), "335311851610699281684828783")
    }
}
