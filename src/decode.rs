use fs_err::OpenOptions;
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::constants::{CR, DEFAULT_LINE_SIZE, DOT, ESCAPE, LF, NUL, SPACE};
use super::errors::DecodeError;

/// Options for decoding.
/// The entry point for decoding from a file or (TCP) stream to an output directory.
#[derive(Debug)]
pub struct DecodeOptions<P> {
    output_dir: P,
}

impl<P> DecodeOptions<P>
where
    P: AsRef<Path>,
{
    /// Construct new DecodeOptions using the specified path as output directory.
    /// The output directory is
    pub fn new(output_dir: P) -> DecodeOptions<P> {
        DecodeOptions { output_dir }
    }
    /// Decodes the input file in a new output file.
    ///
    /// If ok, returns the path of the decoded file.
    ///
    /// # Example
    /// ```rust,no_run
    /// let decode_options = yenc::DecodeOptions::new("/tmp/decoded");
    /// decode_options.decode_file("test2.bin.yenc");
    /// ```
    /// # Errors
    /// - when the output file already exists
    /// - when I/O error occurs
    ///
    pub fn decode_file(&self, input_filename: &str) -> Result<Box<Path>, DecodeError> {
        let mut input_file = OpenOptions::new().read(true).open(input_filename)?;
        self.decode_stream(&mut input_file)
    }

    /// Decodes the data from a stream to the specified directory.
    ///
    /// Writes the output to a file with the filename from the header line, and places it in the
    /// output path. The path of the output file is returned as String.
    pub fn decode_stream<R>(&self, read_stream: R) -> Result<Box<Path>, DecodeError>
    where
        R: Read,
    {
        self.decode(read_stream).map(|metadata| {
            let mut output_pathbuf = self.output_dir.as_ref().to_path_buf();
            output_pathbuf.push(metadata.file.name.trim());
            output_pathbuf.into_boxed_path()
        })
    }

    /// Decodes the data from a stream to the specified directory.
    ///
    /// Writes the output to a file with the filename from the header line, and places it in the
    /// output path. [`MetaData`] is returned with details from the header lines.
    ///
    /// # Errors
    ///
    /// This function will return an error if the header or data are invalid/corrupt
    /// or any IO errors occurs while reading/writing.
    pub fn decode<R>(&self, read_stream: R) -> Result<MetaData, DecodeError>
    where
        R: Read,
    {
        decode(read_stream, |header| {
            let mut output_pathbuf = self.output_dir.as_ref().to_path_buf();

            output_pathbuf.push(header.file.name.trim());

            let mut output = OpenOptions::new()
                .create(true)
                .write(true)
                .open(&output_pathbuf)
                .map(BufWriter::new)?;

            if header.file.parts > 1 {
                output.seek(SeekFrom::Start((header.part.begin - 1) as u64))?;
            }

            Ok(output)
        })
    }
}

pub fn decode<R, F, W>(read_stream: R, create_output: F) -> Result<MetaData, DecodeError>
where
    R: Read,
    F: FnOnce(&MetaData) -> Result<W, DecodeError>,
    W: Write,
{
    let mut rdr = BufReader::new(read_stream);

    let header = read_header(&mut rdr)?;
    let output = create_output(&header)?;

    read_remaining(header, &mut rdr, output)
}

/// Metadata of the message.
#[derive(Debug, PartialEq, Eq)]
pub struct MetaData {
    /// Metadata describing the original file.
    file: FileMetaData,
    /// Metadata describing the decoded block.
    part: PartMetaData,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FileMetaData {
    /// The name of the original binary file.
    name: String,
    /// The size of the original unencoded binary.
    size: usize,
    /// The CRC32 checksum of the entire encoded binary.
    crc32: Option<u32>,
    /// The total amount of parts.
    parts: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PartMetaData {
    /// The part number of the part.
    part_number: u32,
    /// The starting point of the block in the original unencoded binary.
    begin: usize,
    /// The ending point of the block in the original unencoded binary.
    end: usize,
    /// The CRC32 checksum of the encoded part.
    crc32: Option<u32>,
}

/// Parse the header lines.
///
/// For single-part binaries, the begin line is parsed.
/// For multi-part binaries, both the begin and the part line are parsed.
///
/// # Errors
///
/// This function will return an error if the header is invalid.
fn read_header<R>(rdr: &mut R) -> Result<MetaData, DecodeError>
where
    R: BufRead,
{
    let mut line_buf = Vec::<u8>::with_capacity(2 * DEFAULT_LINE_SIZE as usize);
    rdr.read_until(LF, &mut line_buf)?;

    if line_buf.starts_with(b"=ybegin ") {
        let begin_line = parse_keywords(&line_buf)?;

        match begin_line {
            Keywords {
                name: Some(Keyword { value: name, .. }),
                size: Some(Keyword { value: size, .. }),
                line_length: Some(_),
                part: Some(Keyword { value: part, .. }),
                total: Some(Keyword { value: total, .. }),
                ..
            } => {
                let mut line_buf = Vec::<u8>::with_capacity(2 * DEFAULT_LINE_SIZE as usize);
                rdr.read_until(LF, &mut line_buf)?;

                if line_buf.starts_with(b"=ypart ") {
                    let part_line = parse_keywords(&line_buf)?;

                    match part_line {
                        Keywords {
                            begin: Some(Keyword { value: begin, .. }),
                            end: Some(Keyword { value: end, .. }),
                            ..
                        } => Ok(MetaData {
                            file: FileMetaData {
                                name,
                                size,
                                crc32: None,
                                parts: total,
                            },
                            part: PartMetaData {
                                part_number: part,
                                begin,
                                end,
                                crc32: None,
                            },
                        }),
                        _ => Err(DecodeError::InvalidHeader {
                            line: buf_to_string(&line_buf),
                            position: line_buf.len(),
                        }),
                    }
                } else {
                    Err(DecodeError::InvalidHeader {
                        line: buf_to_string(&line_buf),
                        position: 0,
                    })
                }
            }
            Keywords {
                part: Some(keyword),
                ..
            } => Err(keyword.unexpected()),
            Keywords {
                total: Some(keyword),
                ..
            } => Err(keyword.unexpected()),
            Keywords {
                name: Some(Keyword { value: name, .. }),
                size: Some(Keyword { value: size, .. }),
                line_length: Some(_),
                ..
            } => Ok(MetaData {
                file: FileMetaData {
                    name,
                    size,
                    crc32: None,
                    parts: 1,
                },
                part: PartMetaData {
                    part_number: 1,
                    begin: 1,
                    end: size,
                    crc32: None,
                },
            }),
            _ => Err(DecodeError::InvalidHeader {
                line: buf_to_string(&line_buf),
                position: line_buf.len(),
            }),
        }
    } else {
        Err(DecodeError::InvalidHeader {
            line: buf_to_string(&line_buf),
            position: 0,
        })
    }
}

/// Parse the footer line.
///
/// After parsing the footer line it verifies the following:
///
/// * For single-part binaries, the footer should contain a value for the size field
/// that is equal to that of the header.
///
/// * For multi-part binaries, the footer should contain a value for the size field
/// that equals the difference between the 'begin' and 'end' fields of the header,
/// a value for the part field that is equal to that of the header, and a value for
/// the total field that is equal to the header.
///
/// # Errors
///
/// This function will return an error if the footer contains values that do not match the header.
fn read_footer(mut header: MetaData, line_buf: &[u8]) -> Result<MetaData, DecodeError> {
    let end_line = parse_keywords(line_buf)?;

    if header.file.parts > 1 {
        match end_line {
            Keywords {
                size: Some(size),
                pcrc32: Some(Keyword { value: pcrc32, .. }),
                part: Some(part),
                total: Some(total),
                crc32,
                ..
            } => {
                // Recompute expected part size.
                let expected_size = 1 + header.part.end - header.part.begin;

                // Verify that the footer contains the expected size.
                size.should_equal(expected_size)?;

                // Verify that part and total in the footer matches the header.
                part.should_equal(header.part.part_number)?;
                total.should_equal(header.file.parts)?;

                header.file.crc32 = crc32.map(Keyword::value);
                header.part.crc32 = Some(pcrc32);

                Ok(header)
            }
            _ => Err(DecodeError::InvalidHeader {
                line: buf_to_string(&line_buf),
                position: line_buf.len(),
            }),
        }
    } else {
        match end_line {
            Keywords {
                part: Some(keyword),
                ..
            } => Err(keyword.unexpected()),
            Keywords {
                total: Some(keyword),
                ..
            } => Err(keyword.unexpected()),
            Keywords {
                pcrc32: Some(keyword),
                ..
            } => Err(keyword.unexpected()),
            Keywords {
                size: Some(size),
                crc32,
                ..
            } => {
                size.should_equal(header.file.size)?;

                let crc32 = crc32.map(Keyword::value);

                header.file.crc32 = crc32;
                header.part.crc32 = crc32;

                Ok(header)
            }
            _ => Err(DecodeError::InvalidHeader {
                line: buf_to_string(&line_buf),
                position: line_buf.len(),
            }),
        }
    }
}

/// Read the remaining bytes and write them to the output.
///
/// # Errors
///
/// This function will return an error if the data is not
/// the expected size or the checksum does not match.
fn read_remaining<R, W>(
    header: MetaData,
    rdr: &mut BufReader<R>,
    mut output: W,
) -> Result<MetaData, DecodeError>
where
    R: Read,
    W: Write,
{
    let mut checksum = crc32fast::Hasher::new();
    let mut actual_size = 0;

    loop {
        let mut line_buf = Vec::<u8>::with_capacity(2 * DEFAULT_LINE_SIZE as usize);
        line_buf.truncate(0);
        let length = rdr.read_until(LF, &mut line_buf)?;

        if length == 0 {
            break;
        }

        if line_buf.starts_with(b"=yend ") {
            let metadata = read_footer(header, &line_buf)?;

            let expected_size = 1 + metadata.part.end - metadata.part.begin;

            if expected_size != actual_size {
                return Err(DecodeError::IncompleteData {
                    expected_size,
                    actual_size,
                });
            }

            if let Some(value) = metadata.part.crc32 {
                if value != checksum.finalize() {
                    return Err(DecodeError::InvalidChecksum);
                }
            }

            return Ok(metadata);
        } else {
            let decoded = decode_buffer(&line_buf)?;
            checksum.update(&decoded);
            actual_size += decoded.len();
            output.write_all(&decoded)?;
        }
    }

    if header.file.parts > 1 {
        Err(DecodeError::IncompleteData {
            expected_size: 1 + header.part.end - header.part.begin,
            actual_size,
        })
    } else {
        Err(DecodeError::IncompleteData {
            expected_size: header.file.size,
            actual_size,
        })
    }
}

/// Decode the encoded byte slice into a vector of bytes.
///
/// Carriage Return (CR) and Line Feed (LF) are ignored.
pub fn decode_buffer(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let mut output = Vec::<u8>::with_capacity(input.len());
    let mut iter = input.iter().cloned().enumerate();
    while let Some((col, byte)) = iter.next() {
        let mut result_byte = byte;
        match byte {
            NUL | CR | LF => {
                // for now, just continue
                continue;
            }
            DOT if col == 0 => match iter.next() {
                Some((_, DOT)) => {}
                Some((_, b)) => {
                    output.push(byte.overflowing_sub(42).0);
                    result_byte = b;
                }
                None => {}
            },
            ESCAPE => {
                match iter.next() {
                    Some((_, b)) => {
                        result_byte = b.overflowing_sub(64).0;
                    }
                    None => {
                        // for now, just continue
                        continue;
                    }
                }
            }
            _ => {}
        }
        output.push(result_byte.overflowing_sub(42).0);
    }
    Ok(output)
}

fn parse_keywords<'a>(line_buf: &'a [u8]) -> Result<Keywords<'a>, DecodeError> {
    #[derive(Debug)]
    enum State {
        Keyword,
        Value,
        End,
    }

    if !is_header_line(line_buf) {
        return Err(DecodeError::InvalidHeader {
            line: buf_to_string(line_buf),
            position: 0,
        });
    }

    let offset = match line_buf.iter().position(|&c| c == b' ') {
        Some(pos) => pos + 1,
        None => {
            return Err(DecodeError::InvalidHeader {
                line: buf_to_string(line_buf),
                position: 9,
            })
        }
    };

    let line_kind = &line_buf[..offset - 1];

    let mut values: Keywords<'_> = Keywords::default();
    let mut state = State::Keyword;

    let mut keyword: &[u8] = &[];
    let mut keyword_start_idx: Option<usize> = None;
    let mut value: &[u8] = &[];
    let mut value_start_idx: Option<usize> = None;

    for (i, &c) in line_buf[offset..].iter().enumerate() {
        let position = i + offset;
        match state {
            State::End => unreachable!(),
            State::Keyword => match c {
                b'a'..=b'z' | b'0'..=b'9' => {
                    if keyword_start_idx.is_none() {
                        keyword_start_idx = Some(position);
                    }
                    keyword = match keyword_start_idx {
                        Some(idx) => &line_buf[idx..=position],
                        None => {
                            return Err(DecodeError::InvalidHeader {
                                line: buf_to_string(line_buf),
                                position,
                            })
                        }
                    };
                }
                b'=' => {
                    if keyword.is_empty() || !is_known_keyword(line_kind, keyword) {
                        return Err(DecodeError::InvalidHeader {
                            line: buf_to_string(line_buf),
                            position,
                        });
                    } else {
                        state = State::Value;
                    }
                }
                CR | LF => {}
                _ => {
                    return Err(DecodeError::InvalidHeader {
                        line: buf_to_string(line_buf),
                        position,
                    });
                }
            },
            State::Value => match c {
                CR => {}
                LF | SPACE if is_end_character(keyword, c) => {
                    state = match c {
                        LF => State::End,
                        SPACE => State::Keyword,
                        _ => unreachable!(),
                    };
                    if let Some(value_start) = value_start_idx {
                        if let Some(keyword_start) = keyword_start_idx {
                            match keyword {
                                b"name" => {
                                    values.name = Some(Keyword {
                                        keyword_start,
                                        value_start,
                                        value: buf_to_string(value),
                                        line_buf,
                                    })
                                }
                                b"size" | b"begin" | b"end" => {
                                    let parsed_value = std::str::from_utf8(value)
                                        .ok()
                                        .and_then(|s| s.parse::<usize>().ok())
                                        .ok_or_else(|| DecodeError::InvalidHeader {
                                            line: buf_to_string(line_buf),
                                            position,
                                        })
                                        .map(|value| Keyword {
                                            keyword_start,
                                            value_start,
                                            value,
                                            line_buf,
                                        })?;

                                    match keyword {
                                        b"size" => {
                                            values.size = Some(parsed_value);
                                        }
                                        b"begin" => {
                                            values.begin = Some(parsed_value);
                                        }
                                        b"end" => {
                                            values.end = Some(parsed_value);
                                        }
                                        _ => unreachable!(),
                                    }
                                }
                                b"crc32" | b"pcrc32" => {
                                    let parsed_value = std::str::from_utf8(value)
                                        .ok()
                                        .and_then(|s| u32::from_str_radix(s, 16).ok())
                                        .ok_or_else(|| DecodeError::InvalidHeader {
                                            line: buf_to_string(line_buf),
                                            position,
                                        })
                                        .map(|value| Keyword {
                                            keyword_start,
                                            value_start,
                                            value,
                                            line_buf,
                                        })?;

                                    match keyword {
                                        b"crc32" => {
                                            values.crc32 = Some(parsed_value);
                                        }
                                        b"pcrc32" => {
                                            values.pcrc32 = Some(parsed_value);
                                        }
                                        _ => unreachable!(),
                                    }
                                }
                                b"part" | b"total" => {
                                    let parsed_value = std::str::from_utf8(value)
                                        .ok()
                                        .and_then(|s| s.parse::<u32>().ok())
                                        .ok_or_else(|| DecodeError::InvalidHeader {
                                            line: buf_to_string(line_buf),
                                            position,
                                        })
                                        .map(|value| Keyword {
                                            keyword_start,
                                            value_start,
                                            value,
                                            line_buf,
                                        })?;

                                    match keyword {
                                        b"part" => {
                                            values.part = Some(parsed_value);
                                        }
                                        b"total" => {
                                            values.total = Some(parsed_value);
                                        }
                                        _ => unreachable!(),
                                    }
                                }
                                b"line" => {
                                    let parsed_value = std::str::from_utf8(value)
                                        .ok()
                                        .and_then(|s| s.parse::<u16>().ok())
                                        .ok_or_else(|| DecodeError::InvalidHeader {
                                            line: buf_to_string(line_buf),
                                            position,
                                        })
                                        .map(|value| Keyword {
                                            keyword_start,
                                            value_start,
                                            value,
                                            line_buf,
                                        })?;

                                    values.line_length = Some(parsed_value);
                                }
                                _ => unreachable!(),
                            }
                        }
                    }
                    keyword_start_idx = None;
                    value_start_idx = None;
                }
                c if is_valid_character(keyword, c) => {
                    let idx = *value_start_idx.get_or_insert(position);
                    value = &line_buf[idx..=position];
                }
                _ => {
                    return Err(DecodeError::InvalidHeader {
                        line: buf_to_string(line_buf),
                        position,
                    })
                }
            },
        };
    }

    Ok(values)
}

fn is_end_character(keyword: &[u8], c: u8) -> bool {
    c == LF || (keyword != b"name" && c == SPACE)
}

fn is_valid_character(keyword: &[u8], c: u8) -> bool {
    match keyword {
        b"name" => true,
        b"size" | b"line" | b"part" | b"total" | b"begin" | b"end" => matches!(c, b'0'..=b'9'),
        b"crc32" | b"pcrc32" => matches!(c, b'0'..=b'9' | b'A'..=b'F' | b'a'..=b'f'),
        _ => false,
    }
}

#[derive(Debug)]
struct Keywords<'a> {
    name: Option<Keyword<'a, String>>,
    size: Option<Keyword<'a, usize>>,
    line_length: Option<Keyword<'a, u16>>,
    begin: Option<Keyword<'a, usize>>,
    end: Option<Keyword<'a, usize>>,
    pcrc32: Option<Keyword<'a, u32>>,
    crc32: Option<Keyword<'a, u32>>,
    part: Option<Keyword<'a, u32>>,
    total: Option<Keyword<'a, u32>>,
}

#[derive(Debug, PartialEq, Eq)]
struct Keyword<'a, T> {
    keyword_start: usize,
    value_start: usize,
    value: T,
    line_buf: &'a [u8],
}

impl<T> Keyword<'_, T> {
    fn value(self) -> T {
        self.value
    }

    fn unexpected(&self) -> DecodeError {
        DecodeError::InvalidHeader {
            line: buf_to_string(self.line_buf),
            position: self.keyword_start,
        }
    }

    fn should_equal(&self, expected_value: T) -> Result<T, DecodeError>
    where
        T: PartialEq,
    {
        if self.value != expected_value {
            self.unexpected_value()
        } else {
            Ok(expected_value)
        }
    }

    fn unexpected_value(&self) -> Result<T, DecodeError> {
        Err(DecodeError::InvalidHeader {
            line: buf_to_string(self.line_buf),
            position: self.value_start,
        })
    }
}

impl<'a> Default for Keywords<'a> {
    fn default() -> Self {
        Self {
            name: Default::default(),
            size: Default::default(),
            line_length: Default::default(),
            begin: Default::default(),
            end: Default::default(),
            pcrc32: Default::default(),
            crc32: Default::default(),
            part: Default::default(),
            total: Default::default(),
        }
    }
}

fn is_header_line(line_buf: &[u8]) -> bool {
    line_buf.starts_with(b"=ybegin ")
        || line_buf.starts_with(b"=yend ")
        || line_buf.starts_with(b"=ypart ")
}

fn buf_to_string(line_buf: &[u8]) -> String {
    String::from_utf8_lossy(line_buf).to_string()
}

fn is_known_keyword(line_kind: &[u8], keyword_slice: &[u8]) -> bool {
    line_kind == b"=ybegin"
        && matches!(
            keyword_slice,
            b"line" | b"name" | b"part" | b"size" | b"total"
        )
        || line_kind == b"=ypart" && matches!(keyword_slice, b"begin" | b"end")
        || line_kind == b"=yend"
            && matches!(
                keyword_slice,
                b"crc32" | b"part" | b"pcrc32" | b"size" | b"total"
            )
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use std::io::BufReader;

    use crate::{
        decode::{FileMetaData, Keyword, PartMetaData},
        MetaData,
    };

    use super::{decode_buffer, parse_keywords, read_footer, read_header};

    #[test]
    fn read_valid_single_part_footer() {
        let header = MetaData {
            file: FileMetaData {
                name: "CatOnKeyboardInSpace001.jpg".to_string(),
                size: 26624,
                crc32: None,
                parts: 1,
            },
            part: PartMetaData {
                part_number: 1,
                begin: 1,
                end: 26624,
                crc32: None,
            },
        };
        let read_result = read_footer(header, b"=yend size=26624 crc32=ff00ff00\n");
        assert!(read_result.is_ok());
        let metadata = read_result.unwrap();
        assert_eq!(
            MetaData {
                file: FileMetaData {
                    name: "CatOnKeyboardInSpace001.jpg".to_string(),
                    size: 26624,
                    crc32: Some(0xff00ff00),
                    parts: 1,
                },
                part: PartMetaData {
                    part_number: 1,
                    begin: 1,
                    end: 26624,
                    crc32: Some(0xff00ff00)
                }
            },
            metadata
        );
    }

    #[test]
    fn read_valid_single_part_footer_without_crc32() {
        let header = MetaData {
            file: FileMetaData {
                name: "CatOnKeyboardInSpace001.jpg".to_string(),
                size: 26624,
                crc32: None,
                parts: 1,
            },
            part: PartMetaData {
                part_number: 1,
                begin: 1,
                end: 26624,
                crc32: None,
            },
        };
        let read_result = read_footer(header, b"=yend size=26624\n");
        assert!(read_result.is_ok());
        let metadata = read_result.unwrap();
        assert_eq!(
            MetaData {
                file: FileMetaData {
                    name: "CatOnKeyboardInSpace001.jpg".to_string(),
                    size: 26624,
                    crc32: None,
                    parts: 1,
                },
                part: PartMetaData {
                    part_number: 1,
                    begin: 1,
                    end: 26624,
                    crc32: None
                }
            },
            metadata
        );
    }

    // TODO read_valid_multi_part_footer

    #[test]
    fn read_single_part_header_missing_line_length() {
        let mut rdr = BufReader::new(std::io::Cursor::new(
            b"=ybegin size=26624 name=CatOnKeyboardInSpace001.jpg\n",
        ));
        let read_result = read_header(&mut rdr);
        assert!(read_result.is_err());
    }

    #[test]
    fn read_single_part_header_missing_size() {
        let mut rdr = BufReader::new(std::io::Cursor::new(
            b"=ybegin line=128 name=CatOnKeyboardInSpace001.jpg\n",
        ));
        let read_result = read_header(&mut rdr);
        assert!(read_result.is_err());
    }

    #[test]
    fn read_single_part_header_missing_name() {
        let mut rdr = BufReader::new(std::io::Cursor::new(b"=ybegin size=26624 line=128\n"));
        let read_result = read_header(&mut rdr);
        assert!(read_result.is_err());
    }

    #[test]
    fn read_valid_single_part_header() {
        let mut rdr = BufReader::new(std::io::Cursor::new(
            b"=ybegin size=26624 line=128 name=CatOnKeyboardInSpace001.jpg\n",
        ));
        let read_result = read_header(&mut rdr);
        assert!(read_result.is_ok());
        let header = read_result.unwrap();
        assert_eq!(
            MetaData {
                file: FileMetaData {
                    name: "CatOnKeyboardInSpace001.jpg".to_string(),
                    size: 26624,
                    crc32: None,
                    parts: 1,
                },
                part: PartMetaData {
                    part_number: 1,
                    begin: 1,
                    end: 26624,
                    crc32: None,
                },
            },
            header
        );
    }

    #[test]
    fn read_multi_part_header_missing_total() {
        let mut rdr = BufReader::new(std::io::Cursor::new(
            b"=ybegin size=26624 line=128 part=1 name=CatOnKeyboardInSpace001.jpg\n=ypart begin=0 end=1024\n",
        ));
        let read_result = read_header(&mut rdr);
        assert!(read_result.is_err());
    }

    #[test]
    fn read_multi_part_header_missing_part() {
        let mut rdr = BufReader::new(std::io::Cursor::new(
            b"=ybegin size=26624 line=128 total=27 name=CatOnKeyboardInSpace001.jpg\n=ypart begin=0 end=1024\n",
        ));
        let read_result = read_header(&mut rdr);
        assert!(read_result.is_err());
    }

    #[test]
    fn read_multi_part_header_missing_begin() {
        let mut rdr = BufReader::new(std::io::Cursor::new(
            b"=ybegin size=26624 line=128 part=1 total=27 name=CatOnKeyboardInSpace001.jpg\n=ypart end=1024\n",
        ));
        let read_result = read_header(&mut rdr);
        assert!(read_result.is_err());
    }

    #[test]
    fn read_multi_part_header_missing_end() {
        let mut rdr = BufReader::new(std::io::Cursor::new(
            b"=ybegin size=26624 line=128 part=1 total=27 name=CatOnKeyboardInSpace001.jpg\n=ypart begin=0\n",
        ));
        let read_result = read_header(&mut rdr);
        assert!(read_result.is_err());
    }

    #[test]
    fn read_valid_multi_part_header() {
        let mut rdr = BufReader::new(std::io::Cursor::new(
            b"=ybegin size=26624 line=128 part=1 total=27 name=CatOnKeyboardInSpace001.jpg\n=ypart begin=1 end=1024\n",
        ));
        let read_result = read_header(&mut rdr);
        assert!(read_result.is_ok());
        let header = read_result.unwrap();
        assert_eq!(
            MetaData {
                file: FileMetaData {
                    name: "CatOnKeyboardInSpace001.jpg".to_string(),
                    size: 26624,
                    crc32: None,
                    parts: 27,
                },
                part: PartMetaData {
                    part_number: 1,
                    begin: 1,
                    end: 1024,
                    crc32: None,
                },
            },
            header
        );
    }

    #[test]
    fn parse_valid_footer_end_nl() {
        let parse_result = parse_keywords(b"=yend size=26624 part=1 pcrc32=ae052b48\n");
        assert!(parse_result.is_ok());
        let metadata = parse_result.unwrap();
        assert_eq!(
            Some(Keyword {
                keyword_start: 17,
                value_start: 22,
                value: 1,
                line_buf: b"=yend size=26624 part=1 pcrc32=ae052b48\n"
            }),
            metadata.part
        );
        assert_eq!(
            Some(Keyword {
                keyword_start: 6,
                value_start: 11,
                value: 26624,
                line_buf: b"=yend size=26624 part=1 pcrc32=ae052b48\n"
            }),
            metadata.size
        );
        assert_eq!(
            Some(Keyword {
                keyword_start: 24,
                value_start: 31,
                value: 0xae05_2b48,
                line_buf: b"=yend size=26624 part=1 pcrc32=ae052b48\n"
            }),
            metadata.pcrc32
        );
        assert!(metadata.crc32.is_none());
    }

    #[test]
    fn parse_valid_footer_end_crlf() {
        let parse_result =
            parse_keywords(b"=yend size=26624 part=1 pcrc32=ae052b48 crc32=ff00ff00\r\n");
        assert!(parse_result.is_ok());
        let metadata = parse_result.unwrap();
        assert_eq!(
            Some(Keyword {
                keyword_start: 17,
                value_start: 22,
                value: 1,
                line_buf: b"=yend size=26624 part=1 pcrc32=ae052b48 crc32=ff00ff00\r\n"
            }),
            metadata.part
        );
        assert_eq!(
            Some(Keyword {
                keyword_start: 6,
                value_start: 11,
                value: 26624,
                line_buf: b"=yend size=26624 part=1 pcrc32=ae052b48 crc32=ff00ff00\r\n"
            }),
            metadata.size
        );
        assert_eq!(
            Some(Keyword {
                keyword_start: 24,
                value_start: 31,
                value: 0xae05_2b48,
                line_buf: b"=yend size=26624 part=1 pcrc32=ae052b48 crc32=ff00ff00\r\n"
            }),
            metadata.pcrc32
        );
        assert_eq!(
            Some(Keyword {
                keyword_start: 40,
                value_start: 46,
                value: 0xff00_ff00,
                line_buf: b"=yend size=26624 part=1 pcrc32=ae052b48 crc32=ff00ff00\r\n"
            }),
            metadata.crc32
        );
    }

    #[test]
    fn parse_valid_footer_end_space() {
        let parse_result = parse_keywords(b"=yend size=26624 part=1 pcrc32=ae052b48 \n");
        assert!(parse_result.is_ok());
        let metadata = parse_result.unwrap();
        assert_eq!(
            Some(Keyword {
                keyword_start: 17,
                value_start: 22,
                value: 1,
                line_buf: b"=yend size=26624 part=1 pcrc32=ae052b48 \n"
            }),
            metadata.part
        );
        assert_eq!(
            Some(Keyword {
                keyword_start: 6,
                value_start: 11,
                value: 26624,
                line_buf: b"=yend size=26624 part=1 pcrc32=ae052b48 \n"
            }),
            metadata.size
        );
        assert_eq!(
            Some(Keyword {
                keyword_start: 24,
                value_start: 31,
                value: 0xae05_2b48,
                line_buf: b"=yend size=26624 part=1 pcrc32=ae052b48 \n"
            }),
            metadata.pcrc32
        );
    }

    #[test]
    fn parse_valid_header_begin() {
        let parse_result = parse_keywords(
            b"=ybegin part=1 line=128 size=189463 name=CatOnKeyboardInSpace001.jpg\n",
        );
        assert!(parse_result.is_ok());
        let metadata = parse_result.unwrap();
        assert_eq!(
            Some(Keyword {
                keyword_start: 8,
                value_start: 13,
                value: 1,
                line_buf: b"=ybegin part=1 line=128 size=189463 name=CatOnKeyboardInSpace001.jpg\n"
            }),
            metadata.part
        );
        assert_eq!(
            Some(Keyword {
                keyword_start: 24,
                value_start: 29,
                value: 189_463,
                line_buf: b"=ybegin part=1 line=128 size=189463 name=CatOnKeyboardInSpace001.jpg\n"
            }),
            metadata.size
        );
        assert_eq!(
            Some(Keyword {
                keyword_start: 15,
                value_start: 20,
                value: 128,
                line_buf: b"=ybegin part=1 line=128 size=189463 name=CatOnKeyboardInSpace001.jpg\n"
            }),
            metadata.line_length
        );
        assert_eq!(
            Some(Keyword {
                keyword_start: 36,
                value_start: 41,
                value: "CatOnKeyboardInSpace001.jpg".to_string(),
                line_buf: b"=ybegin part=1 line=128 size=189463 name=CatOnKeyboardInSpace001.jpg\n"
            }),
            metadata.name
        );
    }

    #[test]
    fn parse_valid_header_part() {
        let parse_result = parse_keywords(b"=ypart begin=1 end=189463\n");
        assert!(parse_result.is_ok());
        let metadata = parse_result.unwrap();
        assert_eq!(
            Some(Keyword {
                keyword_start: 7,
                value_start: 13,
                value: 1,
                line_buf: b"=ypart begin=1 end=189463\n"
            }),
            metadata.begin
        );
        assert_eq!(
            Some(Keyword {
                keyword_start: 15,
                value_start: 19,
                value: 189_463,
                line_buf: b"=ypart begin=1 end=189463\n"
            }),
            metadata.end
        );
    }

    #[test]
    fn invalid_header_tag() {
        let parse_result = parse_keywords(b"=yparts begin=1 end=189463\n");
        assert!(parse_result.is_err());
    }

    #[test]
    fn invalid_header_unknown_keyword() {
        let parse_result = parse_keywords(b"=ybegin parts=1 total=4 name=party.jpg\r\n");
        assert!(parse_result.is_err());
    }

    #[test]
    fn invalid_header_invalid_begin() {
        let parse_result = parse_keywords(b"=ypart begin=a end=189463\n");
        assert!(parse_result.is_err());
    }

    #[test]
    fn invalid_header_invalid_end() {
        let parse_result = parse_keywords(b"=ypart begin=1 end=18_9463\n");
        assert!(parse_result.is_err());
    }

    #[test]
    fn invalid_header_empty_keyword() {
        let parse_result = parse_keywords(b"=ypart =1 end=189463\n");
        assert!(parse_result.is_err());
    }

    #[test]
    fn decode_invalid() {
        assert!(decode_buffer(&[b'=']).unwrap().is_empty());
    }

    #[test]
    fn decode_valid_ff() {
        assert_eq!(&vec![0xff - 0x2A], &decode_buffer(&[0xff]).unwrap());
    }

    #[test]
    fn decode_valid_01() {
        assert_eq!(&vec![0xff - 0x28], &decode_buffer(&[0x01]).unwrap());
    }

    #[test]
    fn decode_valid_esc_ff() {
        assert_eq!(
            &vec![0xff - 0x40 - 0x2A],
            &decode_buffer(&[b'=', 0xff]).unwrap()
        );
    }

    #[test]
    fn decode_valid_esc_01() {
        assert_eq!(
            &vec![0xff - 0x40 - 0x2A + 2],
            &decode_buffer(&[b'=', 0x01]).unwrap()
        );
    }

    #[test]
    fn decode_valid_prepended_dots() {
        assert_eq!(&vec![b'.' - 0x2A], &decode_buffer(b"..").unwrap());
    }

    #[test]
    fn decode_valid_prepended_single_dot() {
        assert_eq!(
            &vec![b'.' - 0x2A, 0xff - 0x2A],
            &decode_buffer(&[b'.', 0xff]).unwrap()
        );
    }
}
