//! RFC 4648 base32, lowercase, unpadded — the alphabet iroh's own tickets
//! use — over caller buffers.

use rusty_esp_core::error::{Error, Result};

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Characters needed to encode `n` bytes.
#[must_use]
pub const fn encoded_len(n: usize) -> usize {
    (n * 8).div_ceil(5)
}

/// Bytes produced by decoding `chars` characters (ignoring any invalid tail).
#[must_use]
pub const fn decoded_len(chars: usize) -> usize {
    chars * 5 / 8
}

/// Encode `input` into `out`; returns the text.
pub fn encode<'o>(input: &[u8], out: &'o mut [u8]) -> Result<&'o str> {
    let need = encoded_len(input.len());
    if out.len() < need {
        return Err(Error::BufferTooSmall { needed: need });
    }
    let mut acc: u16 = 0;
    let mut bits = 0u8;
    let mut w = 0usize;
    for &b in input {
        acc = (acc << 8) | u16::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out[w] = ALPHABET[usize::from((acc >> bits) & 31)];
            w += 1;
        }
    }
    if bits > 0 {
        out[w] = ALPHABET[usize::from((acc << (5 - bits)) & 31)];
        w += 1;
    }
    debug_assert_eq!(w, need);
    // SAFETY-free: every byte written is from the ASCII alphabet.
    core::str::from_utf8(&out[..w]).map_err(|_| Error::InvalidFormat)
}

fn value(c: u8) -> Option<u8> {
    match c {
        b'a'..=b'z' => Some(c - b'a'),
        b'A'..=b'Z' => Some(c - b'A'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

/// Decode `text` into `out`; returns the byte length. Case-insensitive;
/// padding is not accepted.
pub fn decode(text: &str, out: &mut [u8]) -> Result<usize> {
    let need = decoded_len(text.len());
    if out.len() < need {
        return Err(Error::BufferTooSmall { needed: need });
    }
    let mut acc: u16 = 0;
    let mut bits = 0u8;
    let mut w = 0usize;
    for &c in text.as_bytes() {
        let v = value(c).ok_or(Error::InvalidFormat)?;
        acc = (acc << 5) | u16::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[w] = (acc >> bits) as u8;
            w += 1;
        }
    }
    // Leftover bits must be zero padding of a whole encoding.
    if bits >= 5 || (acc & ((1 << bits) - 1)) != 0 {
        return Err(Error::InvalidFormat);
    }
    Ok(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors_lowercase() {
        let cases: [(&[u8], &str); 4] = [
            (b"", ""),
            (b"f", "my"),
            (b"foobar", "mzxw6ytboi"),
            (b"fooba", "mzxw6ytb"),
        ];
        let mut buf = [0u8; 32];
        for (input, text) in cases {
            assert_eq!(encode(input, &mut buf).unwrap(), text);
            let mut back = [0u8; 16];
            let n = decode(text, &mut back).unwrap();
            assert_eq!(&back[..n], input);
            let n2 = decode(&text.to_uppercase(), &mut back).unwrap();
            assert_eq!(&back[..n2], input);
        }
    }

    #[test]
    fn round_trips_all_lengths_and_rejects_garbage() {
        let data: [u8; 40] = core::array::from_fn(|i| (i * 37 + 11) as u8);
        let mut text = [0u8; 64];
        let mut back = [0u8; 40];
        for n in 0..=40 {
            let t = encode(&data[..n], &mut text).unwrap();
            assert_eq!(t.len(), encoded_len(n));
            let m = decode(t, &mut back).unwrap();
            assert_eq!(&back[..m], &data[..n]);
        }
        assert_eq!(
            decode("mzxw6ytb=", &mut back).err(),
            Some(Error::InvalidFormat)
        );
        assert_eq!(decode("m1", &mut back).err(), Some(Error::InvalidFormat));
        // A dangling non-zero tail is not a valid encoding.
        assert_eq!(decode("mz", &mut back).err(), Some(Error::InvalidFormat));
        assert_eq!(
            encode(b"abc", &mut [0u8; 4]).err(),
            Some(Error::BufferTooSmall { needed: 5 })
        );
    }
}
