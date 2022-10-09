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

/// Metadata contained in the header lines.
#[derive(Debug)]
pub enum MetaData {
    /// Describes a single-part binary.
    Single {
        /// The name of the original binary file.
        name: String,
        /// The size of the original unencoded binary file.
        size: usize,
        /// The CRC32 checksum of the entire encoded binary.
        crc32: Option<u32>,
    },
    /// Describes part of a multi-part binary.
    Multi {
        /// The name of the original binary file.
        name: String,
        /// The size of the original unencoded binary.
        size: usize,
        /// The CRC32 checksum of the entire encoded binary.
        crc32: Option<u32>,
        /// The total amount of parts.
        total: u32,
        /// The part number of the encoded part.
        part: u32,
        /// The starting point of the block in the original unencoded binary.
        begin: usize,
        /// The ending point of the block in the original unencoded binary.
        end: usize,
        /// The CRC32 checksum of the encoded part.
        pcrc32: u32,
    },
}

impl MetaData {
    /// Returns the filename of the original unencoded binary.
    pub fn name(&self) -> &str {
        match self {
            Self::Single { name, .. } => &name,
            Self::Multi { name, .. } => &name,
        }
    }

    /// Returns the size of the original unencoded binary.
    pub fn size(&self) -> usize {
        match self {
            Self::Single { size, .. } => *size,
            Self::Multi { size, .. } => *size,
        }
    }

    /// Returns the CRC32 checksum of the original unencoded binary.
    pub fn crc32(&self) -> Option<u32> {
        match self {
            Self::Single { crc32, .. } => *crc32,
            Self::Multi { crc32, .. } => *crc32,
        }
    }
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
            output_pathbuf.push(metadata.name().trim());
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
        let mut rdr = BufReader::new(read_stream);
        let header = read_header(&mut rdr)?;

        let mut output_pathbuf = self.output_dir.as_ref().to_path_buf();

        output_pathbuf.push(header.name().trim());

        let mut output = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&output_pathbuf)
            .map(BufWriter::new)?;

        match header {
            Header::Single { .. } => read_remaining(header, &mut rdr, output),

            Header::Multi { begin, .. } => {
                output.seek(SeekFrom::Start((begin - 1) as u64))?;
                read_remaining(header, &mut rdr, output)
            }
        }
    }
}

/// Parse the header lines.
///
/// For single-part binaries, the begin line is parsed.
/// For multi-part binaries, both the begin and the part line are parsed.
///
/// # Errors
///
/// This function will return an error if the header is invalid.
fn read_header<R>(rdr: &mut BufReader<R>) -> Result<Header, DecodeError>
where
    R: Read,
{
    let mut line_buf = Vec::<u8>::with_capacity(2 * DEFAULT_LINE_SIZE as usize);
    rdr.read_until(LF, &mut line_buf)?;

    if line_buf.starts_with(b"=ybegin ") {
        let begin_line = parse_keywords(&line_buf)?;

        match begin_line {
            Keywords {
                begin: Some(keyword),
                ..
            } => Err(keyword.unexpected()),
            Keywords {
                end: Some(keyword), ..
            } => Err(keyword.unexpected()),
            Keywords {
                crc32: Some(keyword),
                ..
            } => Err(keyword.unexpected()),
            Keywords {
                pcrc32: Some(keyword),
                ..
            } => Err(keyword.unexpected()),
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
                        } => Ok(Header::Multi {
                            name,
                            size,
                            part,
                            total,
                            begin,
                            end,
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
            } => Ok(Header::Single { name, size }),
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

#[derive(Debug, PartialEq, Eq)]
enum Header {
    Single {
        name: String,
        size: usize,
    },
    Multi {
        name: String,
        size: usize,
        part: u32,
        total: u32,
        begin: usize,
        end: usize,
    },
}

impl Header {
    pub fn name(&self) -> &str {
        match self {
            Header::Single { name, .. } => &name,
            Header::Multi { name, .. } => &name,
        }
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
fn read_footer(header: Header, line_buf: &[u8]) -> Result<MetaData, DecodeError> {
    let end_line = parse_keywords(line_buf)?;

    match header {
        Header::Single {
            name,
            size: expected_size,
            ..
        } => {
            return match end_line {
                Keywords {
                    name: Some(keyword),
                    ..
                } => Err(keyword.unexpected()),
                Keywords {
                    line_length: Some(keyword),
                    ..
                } => Err(keyword.unexpected()),
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
                    begin: Some(keyword),
                    ..
                } => Err(keyword.unexpected()),
                Keywords {
                    end: Some(keyword), ..
                } => Err(keyword.unexpected()),
                Keywords {
                    size: Some(size),
                    crc32,
                    ..
                } => {
                    size.expect(expected_size)?;

                    Ok(MetaData::Single {
                        name,
                        size: expected_size,
                        crc32: crc32.map(Keyword::value),
                    })
                }
                _ => Err(DecodeError::InvalidHeader {
                    line: buf_to_string(&line_buf),
                    position: line_buf.len(),
                }),
            }
        }

        Header::Multi {
            name,
            begin,
            end,
            part: expected_part,
            total: expected_total,
            size: total_size,
            ..
        } => {
            return match end_line {
                Keywords {
                    name: Some(keyword),
                    ..
                } => Err(keyword.unexpected()),
                Keywords {
                    line_length: Some(keyword),
                    ..
                } => Err(keyword.unexpected()),
                Keywords {
                    begin: Some(keyword),
                    ..
                } => Err(keyword.unexpected()),
                Keywords {
                    end: Some(keyword), ..
                } => Err(keyword.unexpected()),
                Keywords {
                    size: Some(size),
                    pcrc32: Some(Keyword { value: pcrc32, .. }),
                    part: Some(part),
                    total: Some(total),
                    crc32,
                    ..
                } => {
                    // Recompute expected part size.
                    let expected_size = end - begin;

                    // Verify that the footer contains the expected size.
                    size.expect(expected_size)?;

                    // Verify that part and total in the footer matches the header.
                    let part = part.expect(expected_part)?;
                    let total = total.expect(expected_total)?;

                    Ok(MetaData::Multi {
                        name,
                        size: total_size,
                        crc32: crc32.map(Keyword::value),
                        total,
                        part,
                        begin,
                        end,
                        pcrc32,
                    })
                }
                _ => Err(DecodeError::InvalidHeader {
                    line: buf_to_string(&line_buf),
                    position: line_buf.len(),
                }),
            };
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
    header: Header,
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

            return match metadata {
                MetaData::Single {
                    size: expected_size,
                    crc32,
                    ..
                } => {
                    if expected_size != actual_size {
                        return Err(DecodeError::IncompleteData {
                            expected_size,
                            actual_size,
                        });
                    }

                    if let Some(value) = crc32 {
                        if value != checksum.finalize() {
                            return Err(DecodeError::InvalidChecksum);
                        }
                    }

                    Ok(metadata)
                }

                MetaData::Multi {
                    begin, end, pcrc32, ..
                } => {
                    let expected_size = end - begin;

                    if expected_size != actual_size {
                        return Err(DecodeError::IncompleteData {
                            expected_size,
                            actual_size,
                        });
                    }

                    if pcrc32 != checksum.finalize() {
                        return Err(DecodeError::InvalidChecksum);
                    }

                    Ok(metadata)
                }
            };
        } else {
            let decoded = decode_buffer(&line_buf)?;
            checksum.update(&decoded);
            actual_size += decoded.len();
            output.write_all(&decoded)?;
        }
    }

    match header {
        Header::Single {
            size: expected_size,
            ..
        } => {
            return Err(DecodeError::IncompleteData {
                expected_size,
                actual_size,
            });
        }
        Header::Multi { begin, end, .. } => {
            let expected_size = end - begin;
            return Err(DecodeError::IncompleteData {
                expected_size,
                actual_size,
            });
        }
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
                    if keyword.is_empty() || !is_known_keyword(keyword) {
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
            State::Value => match keyword {
                b"name" => match c {
                    CR => {}
                    LF => {
                        state = State::End;
                        if let Some(value_start) = value_start_idx {
                            if let Some(keyword_start) = keyword_start_idx {
                                values.name = Some(Keyword {
                                    keyword_start,
                                    value_start,
                                    value: buf_to_string(value),
                                    line_buf,
                                });
                            }
                        }
                    }
                    _ => {
                        if value_start_idx.is_none() {
                            value_start_idx = Some(position);
                        }
                        value = match value_start_idx {
                            Some(idx) => &line_buf[idx..=position],
                            None => {
                                return Err(DecodeError::InvalidHeader {
                                    line: buf_to_string(line_buf),
                                    position,
                                })
                            }
                        };
                    }
                },
                b"size" => match c {
                    b'0'..=b'9' => {
                        if value_start_idx.is_none() {
                            value_start_idx = Some(position);
                        }
                        value = match value_start_idx {
                            Some(idx) => &line_buf[idx..=position],
                            None => {
                                return Err(DecodeError::InvalidHeader {
                                    line: buf_to_string(line_buf),
                                    position,
                                })
                            }
                        };
                    }
                    SPACE => {
                        match String::from_utf8_lossy(value).parse::<usize>() {
                            Ok(value) => {
                                if let Some(value_start) = value_start_idx {
                                    if let Some(keyword_start) = keyword_start_idx {
                                        values.size = Some(Keyword {
                                            keyword_start,
                                            value_start,
                                            value,
                                            line_buf,
                                        });
                                    }
                                }
                            }
                            Err(_) => {
                                return Err(DecodeError::InvalidHeader {
                                    line: buf_to_string(line_buf),
                                    position,
                                })
                            }
                        };
                        state = State::Keyword;
                        keyword_start_idx = None;
                        value_start_idx = None;
                    }
                    _ => {
                        return Err(DecodeError::InvalidHeader {
                            line: buf_to_string(line_buf),
                            position,
                        });
                    }
                },
                b"begin" | b"end" => match c {
                    b'0'..=b'9' => {
                        if value_start_idx.is_none() {
                            value_start_idx = Some(position);
                        }
                        value = match value_start_idx {
                            Some(idx) => &line_buf[idx..=position],
                            None => {
                                return Err(DecodeError::InvalidHeader {
                                    line: buf_to_string(line_buf),
                                    position,
                                })
                            }
                        };
                    }
                    SPACE | LF | CR => {
                        let value =
                            String::from_utf8_lossy(value)
                                .parse::<usize>()
                                .map_err(|_| DecodeError::InvalidHeader {
                                    line: buf_to_string(line_buf),
                                    position,
                                })?;

                        if keyword == b"begin" {
                            if let Some(value_start) = value_start_idx {
                                if let Some(keyword_start) = keyword_start_idx {
                                    values.begin = Some(Keyword {
                                        keyword_start,
                                        value_start,
                                        value,
                                        line_buf,
                                    });
                                }
                            }
                        } else {
                            if let Some(value_start) = value_start_idx {
                                if let Some(keyword_start) = keyword_start_idx {
                                    values.end = Some(Keyword {
                                        keyword_start,
                                        value_start,
                                        value,
                                        line_buf,
                                    });
                                }
                            }
                        }
                        state = State::Keyword;
                        keyword_start_idx = None;
                        value_start_idx = None;
                    }
                    _ => {
                        return Err(DecodeError::InvalidHeader {
                            line: buf_to_string(line_buf),
                            position,
                        });
                    }
                },
                b"line" => match c {
                    b'0'..=b'9' => {
                        if value_start_idx.is_none() {
                            value_start_idx = Some(position);
                        }
                        value = match value_start_idx {
                            Some(idx) => &line_buf[idx..=position],
                            None => {
                                return Err(DecodeError::InvalidHeader {
                                    line: buf_to_string(line_buf),
                                    position,
                                })
                            }
                        };
                    }
                    SPACE => {
                        match String::from_utf8_lossy(value).parse::<u16>() {
                            Ok(value) => {
                                if let Some(value_start) = value_start_idx {
                                    if let Some(keyword_start) = keyword_start_idx {
                                        values.line_length = Some(Keyword {
                                            keyword_start,
                                            value_start,
                                            value,
                                            line_buf,
                                        });
                                    }
                                }
                            }
                            Err(_) => {
                                return Err(DecodeError::InvalidHeader {
                                    line: buf_to_string(line_buf),
                                    position,
                                })
                            }
                        };
                        state = State::Keyword;
                        keyword_start_idx = None;
                        value_start_idx = None;
                    }
                    _ => {
                        return Err(DecodeError::InvalidHeader {
                            line: buf_to_string(line_buf),
                            position,
                        });
                    }
                },
                b"part" | b"total" => match c {
                    b'0'..=b'9' => {
                        if value_start_idx.is_none() {
                            value_start_idx = Some(position);
                        }
                        value = match value_start_idx {
                            Some(idx) => &line_buf[idx..=position],
                            None => {
                                return Err(DecodeError::InvalidHeader {
                                    line: buf_to_string(line_buf),
                                    position,
                                })
                            }
                        };
                    }
                    SPACE => {
                        let value =
                            String::from_utf8_lossy(value).parse::<u32>().map_err(|_| {
                                DecodeError::InvalidHeader {
                                    line: buf_to_string(line_buf),
                                    position,
                                }
                            })?;
                        if keyword == b"part" {
                            if let Some(value_start) = value_start_idx {
                                if let Some(keyword_start) = keyword_start_idx {
                                    values.part = Some(Keyword {
                                        keyword_start,
                                        value_start,
                                        value,
                                        line_buf,
                                    });
                                }
                            }
                        } else {
                            if let Some(value_start) = value_start_idx {
                                if let Some(keyword_start) = keyword_start_idx {
                                    values.total = Some(Keyword {
                                        keyword_start,
                                        value_start,
                                        value,
                                        line_buf,
                                    });
                                }
                            }
                        }
                        state = State::Keyword;
                        keyword_start_idx = None;
                        value_start_idx = None;
                    }
                    _ => {
                        return Err(DecodeError::InvalidHeader {
                            line: buf_to_string(line_buf),
                            position,
                        });
                    }
                },
                b"crc32" | b"pcrc32" => match c {
                    b'0'..=b'9' | b'A'..=b'F' | b'a'..=b'f' => {
                        if value_start_idx.is_none() {
                            value_start_idx = Some(position);
                        }
                        value = match value_start_idx {
                            Some(idx) => &line_buf[idx..=position],
                            None => {
                                return Err(DecodeError::InvalidHeader {
                                    line: buf_to_string(line_buf),
                                    position,
                                })
                            }
                        };
                    }
                    SPACE | LF => {
                        state = if c == SPACE {
                            State::Keyword
                        } else {
                            State::End
                        };
                        let value = u32::from_str_radix(&String::from_utf8_lossy(value), 16)
                            .map_err(|_| DecodeError::InvalidHeader {
                                line: buf_to_string(line_buf),
                                position,
                            })?;
                        if keyword == b"crc32" {
                            if let Some(value_start) = value_start_idx {
                                if let Some(keyword_start) = keyword_start_idx {
                                    values.crc32 = Some(Keyword {
                                        keyword_start,
                                        value_start,
                                        value,
                                        line_buf,
                                    });
                                }
                            }
                        } else {
                            if let Some(value_start) = value_start_idx {
                                if let Some(keyword_start) = keyword_start_idx {
                                    values.pcrc32 = Some(Keyword {
                                        keyword_start,
                                        value_start,
                                        value,
                                        line_buf,
                                    });
                                }
                            }
                        }
                        keyword_start_idx = None;
                        value_start_idx = None;
                    }
                    CR => {}
                    _ => {
                        return Err(DecodeError::InvalidHeader {
                            line: buf_to_string(line_buf),
                            position,
                        });
                    }
                },
                _ => unreachable!(),
            },
        };
    }

    Ok(values)
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

    fn expect(&self, expected_value: T) -> Result<T, DecodeError>
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

fn is_known_keyword(keyword_slice: &[u8]) -> bool {
    matches!(
        keyword_slice,
        b"begin" | b"crc32" | b"end" | b"line" | b"name" | b"part" | b"pcrc32" | b"size" | b"total"
    )
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use std::io::BufReader;

    use crate::decode::{Header, Keyword};

    use super::{decode_buffer, parse_keywords, read_header};

    #[test]
    fn read_single_part_header_begin_line_missing_keyword() {
        let mut rdr = BufReader::new(std::io::Cursor::new(
            b"=ybegin size=26624 name=CatOnKeyboardInSpace001.jpg\n",
        ));
        let read_result = read_header(&mut rdr);
        assert!(read_result.is_err());
    }

    #[test]
    fn read_single_part_header_begin_line_unexpected_keyword() {
        let mut rdr = BufReader::new(std::io::Cursor::new(
            b"=ybegin size=26624 line=128 begin=1 name=CatOnKeyboardInSpace001.jpg\n",
        ));
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
            Header::Single {
                name: "CatOnKeyboardInSpace001.jpg".to_string(),
                size: 26624
            },
            header
        );
    }

    #[test]
    fn read_multi_part_header_begin_line_missing_keyword() {
        let mut rdr = BufReader::new(std::io::Cursor::new(
            b"=ybegin size=26624 line=128 part=1 name=CatOnKeyboardInSpace001.jpg\n=ypart begin=0 end=1024\n",
        ));
        let read_result = read_header(&mut rdr);
        assert!(read_result.is_err());
    }

    #[test]
    fn read_multi_part_header_part_line_missing_keyword() {
        let mut rdr = BufReader::new(std::io::Cursor::new(
            b"=ybegin size=26624 line=128 part=1 total=27 name=CatOnKeyboardInSpace001.jpg\n=ypart begin=0\n",
        ));
        let read_result = read_header(&mut rdr);
        assert!(read_result.is_err());
    }

    #[test]
    fn read_valid_multi_part_header() {
        let mut rdr = BufReader::new(std::io::Cursor::new(
            b"=ybegin size=26624 line=128 part=1 total=27 name=CatOnKeyboardInSpace001.jpg\n=ypart begin=0 end=1024\n",
        ));
        let read_result = read_header(&mut rdr);
        assert!(read_result.is_ok());
        let header = read_result.unwrap();
        assert_eq!(
            Header::Multi {
                name: "CatOnKeyboardInSpace001.jpg".to_string(),
                size: 26624,
                part: 1,
                total: 27,
                begin: 0,
                end: 1024,
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
