use base::{LoggedResult, MappedFile, Utf8CStr, WriteExt, log_err};
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::File;
use std::io::{Read, Write};

const UBOOT_MAGIC: u32 = 0x27051956;
const UBOOT_HEADER_SIZE: usize = 64;
pub const UBOOT_HEADER_FILE: &str = ".uboot_header";
const RAMDISK_FILE: &str = "ramdisk.cpio";

const CRC32_TABLE: [u32; 256] = {
    let poly: u32 = 0xEDB88320;
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

fn compute_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }
    crc ^ 0xFFFFFFFF
}

pub fn uboot_is_valid(image: &Utf8CStr) -> bool {
    let Ok(data) = MappedFile::open(image) else {
        return false;
    };
    let data = data.as_ref();
    if data.len() < UBOOT_HEADER_SIZE {
        return false;
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    magic == UBOOT_MAGIC
}

pub fn uboot_unpack(image: &Utf8CStr) -> LoggedResult<()> {
    let data = MappedFile::open(image)?;
    let data = data.as_ref();

    if data.len() < UBOOT_HEADER_SIZE {
        return log_err!("File too small for U-Boot ramdisk header");
    }

    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic != UBOOT_MAGIC {
        return log_err!("Not a U-Boot image (magic {:08x} != {:08x})", magic, UBOOT_MAGIC);
    }

    // Validate header CRC (offset 4, big-endian)
    let stored_header_crc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let mut header_copy = [0u8; UBOOT_HEADER_SIZE];
    header_copy.copy_from_slice(&data[..UBOOT_HEADER_SIZE]);
    header_copy[4..8].fill(0);
    let calc_header_crc = compute_crc32(&header_copy);

    if stored_header_crc != calc_header_crc {
        eprintln!(
            "Warning: U-Boot header CRC mismatch (stored: {:08x}, calculated: {:08x})",
            stored_header_crc, calc_header_crc
        );
    }

    // Validate data CRC (offset 24, big-endian) - warning only
    let stored_data_crc = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
    let body = &data[UBOOT_HEADER_SIZE..];
    let calc_data_crc = compute_crc32(body);

    if stored_data_crc != calc_data_crc {
        eprintln!(
            "Warning: U-Boot data CRC mismatch (stored: {:08x}, calculated: {:08x})",
            stored_data_crc, calc_data_crc
        );
    }

    // Save the 64-byte header
    let mut hdr_file = File::create(UBOOT_HEADER_FILE)?;
    hdr_file.write_all(&data[..UBOOT_HEADER_SIZE])?;
    eprintln!("U-Boot header saved to [{}]", UBOOT_HEADER_FILE);

    // Decompress body (gzip) to ramdisk.cpio
    let mut decoder = MultiGzDecoder::new(body);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;

    let mut out_file = File::create(RAMDISK_FILE)?;
    out_file.write_all(&decompressed)?;
    eprintln!(
        "Ramdisk unpacked to [{}] ({} bytes)",
        RAMDISK_FILE,
        decompressed.len()
    );

    Ok(())
}

pub fn uboot_repack(orig_image: &Utf8CStr, output: &Utf8CStr) -> LoggedResult<()> {
    // Read the ramdisk
    let ramdisk = std::fs::read(RAMDISK_FILE)?;

    // Compress ramdisk with gzip (default level for balance on constrained devices)
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&ramdisk)?;
    let compressed = encoder.finish()?;
    eprintln!("Ramdisk compressed: {} -> {} bytes", ramdisk.len(), compressed.len());

    // Read the saved header
    let mut header = std::fs::read(UBOOT_HEADER_FILE)?;

    if header.len() < UBOOT_HEADER_SIZE {
        return log_err!("Invalid U-Boot header file");
    }

    // Update data size at offset 12 (big-endian u32)
    let body_len = compressed.len() as u32;
    header[12..16].copy_from_slice(&body_len.to_be_bytes());

    // Update data CRC at offset 24 (big-endian u32)
    let body_crc = compute_crc32(&compressed);
    header[24..28].copy_from_slice(&body_crc.to_be_bytes());

    // Update header CRC at offset 4 (big-endian u32)
    // Must zero the CRC field first, then compute
    header[4..8].fill(0);
    let header_crc = compute_crc32(&header[..UBOOT_HEADER_SIZE]);
    header[4..8].copy_from_slice(&header_crc.to_be_bytes());

    // Determine the original image size for partition-aligned output
    let orig_size = std::fs::metadata(orig_image.as_str())?.len() as usize;
    let content_size = UBOOT_HEADER_SIZE + compressed.len();

    if content_size > orig_size {
        return log_err!(
            "Repacked ramdisk ({} bytes) exceeds original image size ({} bytes)",
            content_size,
            orig_size
        );
    }

    // Write output: header + compressed body + zero padding to match original size
    let mut out_file = File::create(output.as_str())?;
    out_file.write_all(&header[..UBOOT_HEADER_SIZE])?;
    out_file.write_all(&compressed)?;

    let padding = orig_size - content_size;
    if padding > 0 {
        out_file.write_zeros(padding)?;
    }

    eprintln!(
        "U-Boot ramdisk repacked to [{}] ({} bytes, padded to {} bytes)",
        output,
        content_size,
        orig_size
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_known_value() {
        // CRC32 of "123456789" should be 0xCBF43926
        let data = b"123456789";
        assert_eq!(compute_crc32(data), 0xCBF43926);
    }

    #[test]
    fn test_crc32_empty() {
        assert_eq!(compute_crc32(&[]), 0x00000000);
    }

    #[test]
    fn test_crc32_single_byte() {
        // CRC32 of [0x00] should be 0xD202EF8D
        assert_eq!(compute_crc32(&[0x00]), 0xD202EF8D);
    }
}
