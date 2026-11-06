use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

use rustix::rand::{GetRandomFlags, getrandom};

pub const NEUTRALIZED_PAYLOAD_MAGIC: &[u8] = b"LAZARET-NEUTRALIZED-PAYLOAD-1\n";
pub const SCRAMBLING_KEY_LENGTH: usize = 32;

pub type ScramblingKey = [u8; SCRAMBLING_KEY_LENGTH];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadEncoding {
    RawPayload,
    NeutralizedPayload { scrambling_key: ScramblingKey },
}

pub fn fresh_scrambling_key() -> io::Result<ScramblingKey> {
    let mut scrambling_key = [0_u8; SCRAMBLING_KEY_LENGTH];
    getrandom(&mut scrambling_key, GetRandomFlags::empty())?;
    Ok(scrambling_key)
}

fn scramble_in_place(
    scrambling_key: &ScramblingKey,
    content_position: u64,
    content_bytes: &mut [u8],
) {
    content_bytes
        .iter_mut()
        .enumerate()
        .for_each(|(byte_offset, content_byte)| {
            let key_position =
                (content_position + byte_offset as u64) % SCRAMBLING_KEY_LENGTH as u64;
            *content_byte ^= scrambling_key[key_position as usize];
        });
}

pub struct PayloadWriter<Destination: Write> {
    destination: Destination,
    payload_encoding: PayloadEncoding,
    content_position: u64,
}

impl<Destination: Write> PayloadWriter<Destination> {
    pub fn starting(
        mut destination: Destination,
        payload_encoding: PayloadEncoding,
    ) -> io::Result<Self> {
        if let PayloadEncoding::NeutralizedPayload { scrambling_key } = &payload_encoding {
            destination.write_all(NEUTRALIZED_PAYLOAD_MAGIC)?;
            destination.write_all(scrambling_key)?;
        }
        Ok(Self {
            destination,
            payload_encoding,
            content_position: 0,
        })
    }
}

impl<Destination: Write> Write for PayloadWriter<Destination> {
    fn write(&mut self, content_bytes: &[u8]) -> io::Result<usize> {
        let written_length = match &self.payload_encoding {
            PayloadEncoding::RawPayload => self.destination.write(content_bytes)?,
            PayloadEncoding::NeutralizedPayload { scrambling_key } => {
                let mut scrambled_bytes = content_bytes.to_vec();
                scramble_in_place(scrambling_key, self.content_position, &mut scrambled_bytes);
                self.destination.write_all(&scrambled_bytes)?;
                content_bytes.len()
            }
        };
        self.content_position += written_length as u64;
        Ok(written_length)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.destination.flush()
    }
}

pub struct PlaintextReader<Source: Read> {
    source: Source,
    payload_encoding: PayloadEncoding,
    content_position: u64,
}

impl<Source: Read> PlaintextReader<Source> {
    pub const fn payload_encoding(&self) -> PayloadEncoding {
        self.payload_encoding
    }
}

impl<Source: Read> Read for PlaintextReader<Source> {
    fn read(&mut self, content_buffer: &mut [u8]) -> io::Result<usize> {
        let read_length = self.source.read(content_buffer)?;
        if let PayloadEncoding::NeutralizedPayload { scrambling_key } = &self.payload_encoding {
            scramble_in_place(
                scrambling_key,
                self.content_position,
                &mut content_buffer[..read_length],
            );
        }
        self.content_position += read_length as u64;
        Ok(read_length)
    }
}

pub fn detect_payload_encoding(payload_file: &mut File) -> io::Result<PayloadEncoding> {
    let header_length = NEUTRALIZED_PAYLOAD_MAGIC.len() + SCRAMBLING_KEY_LENGTH;
    let mut header_bytes = Vec::with_capacity(header_length);
    Read::by_ref(payload_file)
        .take(header_length as u64)
        .read_to_end(&mut header_bytes)?;
    if header_bytes.len() == header_length && header_bytes.starts_with(NEUTRALIZED_PAYLOAD_MAGIC) {
        let mut scrambling_key = [0_u8; SCRAMBLING_KEY_LENGTH];
        scrambling_key.copy_from_slice(&header_bytes[NEUTRALIZED_PAYLOAD_MAGIC.len()..]);
        Ok(PayloadEncoding::NeutralizedPayload { scrambling_key })
    } else {
        payload_file.seek(SeekFrom::Start(0))?;
        Ok(PayloadEncoding::RawPayload)
    }
}

pub fn open_plaintext_reader(mut payload_file: File) -> io::Result<PlaintextReader<File>> {
    let payload_encoding = detect_payload_encoding(&mut payload_file)?;
    Ok(PlaintextReader {
        source: payload_file,
        payload_encoding,
        content_position: 0,
    })
}

#[cfg(test)]
mod quarantine_payload_format_tests {
    use super::*;

    fn neutralized_bytes(plaintext: &[u8], scrambling_key: ScramblingKey) -> Vec<u8> {
        let mut stored_bytes = Vec::new();
        let mut payload_writer = PayloadWriter::starting(
            &mut stored_bytes,
            PayloadEncoding::NeutralizedPayload { scrambling_key },
        )
        .unwrap();
        plaintext
            .chunks(7)
            .for_each(|plaintext_chunk| payload_writer.write_all(plaintext_chunk).unwrap());
        stored_bytes
    }

    fn read_back(stored_bytes: &[u8]) -> (Vec<u8>, PayloadEncoding) {
        let mut stored_file = tempfile::tempfile().unwrap();
        stored_file.write_all(stored_bytes).unwrap();
        stored_file.seek(SeekFrom::Start(0)).unwrap();
        let mut plaintext_reader = open_plaintext_reader(stored_file).unwrap();
        let mut plaintext = Vec::new();
        plaintext_reader.read_to_end(&mut plaintext).unwrap();
        (plaintext, plaintext_reader.payload_encoding())
    }

    const EICAR_PATTERN: &[u8] =
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    #[test]
    fn neutralized_payloads_hide_their_content_and_read_back_exactly() {
        let scrambling_key = fresh_scrambling_key().unwrap();
        let stored_bytes = neutralized_bytes(EICAR_PATTERN, scrambling_key);
        assert!(
            !stored_bytes
                .windows(EICAR_PATTERN.len())
                .any(|stored_window| stored_window == EICAR_PATTERN)
        );
        let (plaintext, payload_encoding) = read_back(&stored_bytes);
        assert_eq!(plaintext, EICAR_PATTERN);
        assert_eq!(
            payload_encoding,
            PayloadEncoding::NeutralizedPayload { scrambling_key }
        );
    }

    #[test]
    fn raw_payloads_including_short_ones_read_back_unchanged() {
        [b"".as_slice(), b"short", EICAR_PATTERN]
            .into_iter()
            .for_each(|raw_content| {
                assert_eq!(
                    read_back(raw_content),
                    (raw_content.to_vec(), PayloadEncoding::RawPayload)
                );
            });
    }

    #[test]
    fn a_raw_file_that_only_starts_like_the_header_stays_raw() {
        let (plaintext, payload_encoding) = read_back(NEUTRALIZED_PAYLOAD_MAGIC);
        assert_eq!(plaintext, NEUTRALIZED_PAYLOAD_MAGIC);
        assert_eq!(payload_encoding, PayloadEncoding::RawPayload);
    }
}
