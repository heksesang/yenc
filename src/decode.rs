use fs_err::OpenOptions;
use std::convert::TryInto;
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};

use std::path::Path;

use crate::parsers::{multipart_yend, singlepart_yend, ypart};

use super::constants::{CR, DEFAULT_LINE_SIZE, DOT, ESCAPE, LF, NUL};
use super::errors::DecodeError;
use super::parsers::ybegin;

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

/// Metadata describing the message.
#[derive(Debug, PartialEq, Eq)]
pub struct MetaData {
    /// Description of the unencoded binary.
    file: FileMetaData,
    /// Description of an encoded part of the binary.
    part: PartMetaData,
}

/// Metadata describing a file.
#[derive(Debug, PartialEq, Eq)]
pub struct FileMetaData {
    /// The name of the file.
    name: String,
    /// The size of the file.
    size: u64,
    /// The CRC32 checksum of the file.
    crc32: Option<u32>,
    /// The number of blocks the file is split into.
    parts: u32,
}

/// Metadata describing an encoded part of a file.
#[derive(Debug, PartialEq, Eq)]
pub struct PartMetaData {
    /// The sequential part number.
    part_number: u32,
    /// The starting point of the block in the original unencoded binary.
    begin: u64,
    /// The ending point of the block in the original unencoded binary.
    end: u64,
    /// The CRC32 checksum of this part.
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

    let s: &str = &String::from_utf8_lossy(&line_buf[..]);

    let BeginInfo {
        line: _,
        size,
        part_tokens,
        name,
    } = use_parser(ybegin)(s)?;

    if let Some(PartInfo { part, total }) = part_tokens {
        let mut line_buf = Vec::<u8>::with_capacity(2 * DEFAULT_LINE_SIZE as usize);
        rdr.read_until(LF, &mut line_buf)?;

        let s: &str = &String::from_utf8_lossy(&line_buf[..]);

        let (begin, end) = use_parser(ypart)(s)?;
        Ok(MetaData {
            file: FileMetaData {
                name: name.to_string(),
                size,
                crc32: None,
                parts: total.unwrap_or_default(),
            },
            part: PartMetaData {
                part_number: part,
                begin,
                end,
                crc32: None,
            },
        })
    } else {
        Ok(MetaData {
            file: FileMetaData {
                name: name.to_string(),
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
    let s: &str = &String::from_utf8_lossy(&line_buf);

    if header.file.parts > 1 {
        let expected_size = 1 + header.part.end - header.part.begin;
        let expected_part = header.part.part_number;
        let expected_part_count = header.file.parts;

        let (pcrc32, crc32) = use_parser(multipart_yend(
            expected_size,
            expected_part,
            Some(expected_part_count),
        ))(s)?;

        header.file.crc32 = crc32;
        header.part.crc32 = Some(pcrc32);

        Ok(header)
    } else {
        let crc32 = use_parser(singlepart_yend(header.file.size))(&s)?;

        header.file.crc32 = crc32;
        header.part.crc32 = crc32;

        Ok(header)
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
                    expected_size: expected_size,
                    actual_size: actual_size,
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
            let decoded_len: u64 = decoded.len().try_into().unwrap();
            actual_size += decoded_len;
            output.write_all(&decoded)?;
        }
    }

    if header.file.parts > 1 {
        Err(DecodeError::IncompleteData {
            expected_size: (1 + header.part.end - header.part.begin),
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

fn use_parser<'a, O, F>(mut parser: F) -> impl FnMut(&'a str) -> Result<O, DecodeError>
where
    F: nom::Parser<&'a str, O, nom::error::VerboseError<&'a str>>,
{
    move |input: &'a str| {
        parser
            .parse(input)
            .map(|(_, out)| out)
            .map_err(|e| (input, e).into())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BeginInfo<'a> {
    pub line: u16,
    pub size: u64,
    pub part_tokens: Option<PartInfo>,
    pub name: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PartInfo {
    pub part: u32,
    pub total: Option<u32>,
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use std::io::BufReader;

    use crate::{
        decode::{FileMetaData, PartMetaData},
        MetaData,
    };

    use super::{decode_buffer, read_footer, read_header};

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
        assert!(read_result.is_ok());
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
        if let Err(ref e) = read_result {
            println!("{e:?}");
        }
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
