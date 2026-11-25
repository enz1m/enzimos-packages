// SPDX-License-Identifier: MIT
//! A bounded still PNG with no metadata, animation, external references or profiles.
use enzimos_platform::{Error, Result, require};
use flate2::{Compression, bufread::ZlibDecoder, write::ZlibEncoder};
use std::io::{Read, Write};
pub(crate) const LIMIT: usize = 3 * 1024 * 1024;
fn crc(bytes: &[u8]) -> u32 {
    let mut sum = !0u32;
    for byte in bytes {
        sum ^= u32::from(*byte);
        for _ in 0..8 {
            sum = (sum >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(sum & 1));
        }
    }
    !sum
}
fn chunk(out: &mut Vec<u8>, kind: [u8; 4], bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    let start = out.len();
    out.extend_from_slice(&kind);
    out.extend_from_slice(bytes);
    out.extend_from_slice(&crc(&out[start..]).to_be_bytes());
}
pub(crate) fn canonical(bytes: &[u8]) -> Result<Vec<u8>> {
    let bad = || Error("login-image-invalid".into());
    require(
        bytes.len() <= LIMIT && bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "login-image-invalid",
    )?;
    let mut at = 8;
    let mut header = None;
    let mut compressed = Vec::new();
    let mut ended = false;
    let mut data_ended = false;
    let mut chunks = 0;
    while at < bytes.len() {
        chunks += 1;
        require(
            chunks <= 1024 && bytes.len() - at >= 12 && !ended,
            "login-image-invalid",
        )?;
        let size = u32::from_be_bytes(bytes[at..at + 4].try_into().map_err(|_| bad())?) as usize;
        require(size <= bytes.len() - at - 12, "login-image-invalid")?;
        let kind = &bytes[at + 4..at + 8];
        let data = &bytes[at + 8..at + 8 + size];
        let actual = u32::from_be_bytes(
            bytes[at + 8 + size..at + 12 + size]
                .try_into()
                .map_err(|_| bad())?,
        );
        require(
            crc(&bytes[at + 4..at + 8 + size]) == actual,
            "login-image-invalid",
        )?;
        match kind {
            b"IHDR" => {
                require(
                    at == 8 && size == 13 && header.is_none(),
                    "login-image-invalid",
                )?;
                header = Some(data);
            }
            b"IDAT" => {
                require(header.is_some() && !data_ended, "login-image-invalid")?;
                compressed.extend_from_slice(data);
            }
            b"IEND" => {
                require(size == 0 && !compressed.is_empty(), "login-image-invalid")?;
                ended = true;
            }
            // Discard bounded ancillary metadata without decoding it. Refuse
            // unknown critical chunks, palettes and animated images outright.
            _ => {
                require(
                    header.is_some()
                        && kind[0].is_ascii_lowercase()
                        && !matches!(kind, b"acTL" | b"fcTL" | b"fdAT"),
                    "login-image-invalid",
                )?;
                if !compressed.is_empty() {
                    data_ended = true;
                }
            }
        }
        at += size + 12;
    }
    let header = header.ok_or_else(bad)?;
    let width = u32::from_be_bytes(header[..4].try_into().map_err(|_| bad())?) as usize;
    let height = u32::from_be_bytes(header[4..8].try_into().map_err(|_| bad())?) as usize;
    require(
        ended
            && (1..=960).contains(&width)
            && (1..=540).contains(&height)
            && header[8] == 8
            && matches!(header[9], 2 | 6)
            && header[10..] == [0, 0, 0],
        "login-image-invalid",
    )?;
    let stride = 1 + width * if header[9] == 6 { 4 } else { 3 };
    let length = stride * height;
    let mut decoder = ZlibDecoder::new(compressed.as_slice());
    let mut pixels = Vec::new();
    decoder
        .by_ref()
        .take((length + 1) as u64)
        .read_to_end(&mut pixels)
        .map_err(|_| bad())?;
    require(
        pixels.len() == length
            && decoder.total_in() == compressed.len() as u64
            && pixels.chunks_exact(stride).all(|row| row[0] <= 4),
        "login-image-invalid",
    )?;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&pixels)?;
    let encoded = encoder.finish()?;
    let mut result = b"\x89PNG\r\n\x1a\n".to_vec();
    chunk(&mut result, *b"IHDR", header);
    chunk(&mut result, *b"IDAT", &encoded);
    chunk(&mut result, *b"IEND", &[]);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_stills_strip_metadata_and_bound_actual_decoded_pixels() {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&[0, 20, 30, 40, 255]).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        let header = [0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0];
        chunk(&mut png, *b"IHDR", &header);
        chunk(&mut png, *b"tEXt", b"private original pathname");
        chunk(&mut png, *b"IDAT", &compressed);
        chunk(&mut png, *b"IEND", &[]);
        let clean = canonical(&png).unwrap();
        assert!(!clean.windows(4).any(|part| part == b"tEXt"));
        assert_eq!(canonical(&clean).unwrap(), clean);
        let mut corrupt = png.clone();
        corrupt[20] ^= 1;
        assert!(canonical(&corrupt).is_err());
        for (width, data) in [(961u32, compressed.as_slice()), (1, &[1, 2, 3][..])] {
            let mut bad_header = header;
            bad_header[..4].copy_from_slice(&width.to_be_bytes());
            let mut bad = b"\x89PNG\r\n\x1a\n".to_vec();
            chunk(&mut bad, *b"IHDR", &bad_header);
            chunk(&mut bad, *b"IDAT", data);
            chunk(&mut bad, *b"IEND", &[]);
            assert_eq!(canonical(&bad).unwrap_err().0, "login-image-invalid");
        }
        let mut trailing = png;
        trailing.extend_from_slice(b"other data");
        assert!(canonical(&trailing).is_err());
    }
}
