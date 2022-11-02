use fs_err::OpenOptions;
use nom::branch::{alt, permutation};
use nom::bytes::complete::{tag, take_until, take_while_m_n};
use nom::character::complete::{line_ending, multispace1, u16, u32, u64};
use nom::combinator::{cond, eof, map, opt};
use nom::error::VerboseError;
use nom::sequence::preceded;
use nom::{IResult, Parser};
use std::convert::TryInto;
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};

use std::path::Path;

use super::constants::{CR, DEFAULT_LINE_SIZE, DOT, ESCAPE, LF, NUL};
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
    size: u64,
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
    begin: u64,
    /// The ending point of the block in the original unencoded binary.
    end: u64,
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

    let s: &str = &String::from_utf8_lossy(&line_buf[..]);

    let (
        _,
        BeginTokens {
            line: _,
            size,
            part_tokens,
            name,
        },
    ) = parse_ybegin::<VerboseError<_>>(s).map_err(|e| DecodeError::from((s, e)))?;

    if let Some(BeginPartTokens { part, total }) = part_tokens {
        let mut line_buf = Vec::<u8>::with_capacity(2 * DEFAULT_LINE_SIZE as usize);
        rdr.read_until(LF, &mut line_buf)?;

        let s: &str = &String::from_utf8_lossy(&line_buf[..]);

        let (_, (begin, end)) = parse_ypart(s).map_err(|e| DecodeError::from((s, e)))?;
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

        let res: IResult<_, _, VerboseError<_>> =
            parse_multipart_yend(expected_size, expected_part, Some(expected_part_count))(s);

        let (_, (pcrc32, crc32)) = res.map_err(|e| DecodeError::from((s, e)))?;
        header.file.crc32 = crc32;
        header.part.crc32 = Some(pcrc32);
        Ok(header)
    } else {
        let res: IResult<_, _, VerboseError<_>> = parse_singlepart_yend(header.file.size)(&s);
        let (_, crc32) = res.map_err(|e| DecodeError::from((s, e)))?;
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

fn parse_ybegin<'a, E>(s: &'a str) -> IResult<&'a str, BeginTokens<'a>, E>
where
    E: nom::error::ParseError<&'a str>,
{
    map(
        preceded(
            tag("=ybegin "),
            permutation((
                parse_keyword("line", u16),
                parse_keyword("size", u64),
                map(
                    opt(permutation((
                        parse_keyword("part", u32),
                        opt(parse_keyword("total", u32)),
                    ))),
                    |part_tokens| part_tokens.map(|(part, total)| BeginPartTokens { part, total }),
                ),
                parse_keyword("name", |s: &'a str| -> IResult<&'a str, &'a str, E> {
                    let (s, value) = take_until("\n")(s)?;
                    Ok((s, value))
                }),
            )),
        ),
        |(line, size, part_tokens, name)| BeginTokens {
            line,
            size,
            part_tokens,
            name,
        },
    )(s)
}

#[derive(Debug, PartialEq, Eq)]
struct BeginTokens<'a> {
    line: u16,
    size: u64,
    part_tokens: Option<BeginPartTokens>,
    name: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
struct BeginPartTokens {
    part: u32,
    total: Option<u32>,
}

fn parse_ypart<'a, E>(s: &'a str) -> IResult<&'a str, (u64, u64), E>
where
    E: nom::error::ParseError<&'a str>,
{
    preceded(
        tag("=ypart "),
        permutation((parse_keyword("begin", u64), parse_keyword("end", u64))),
    )(s)
}

fn parse_multipart_yend<'a, E>(
    size: u64,
    part: u32,
    total: Option<u32>,
) -> impl Fn(&'a str) -> IResult<&'a str, (u32, Option<u32>), E>
where
    E: nom::error::ParseError<&'a str>,
{
    move |s: &'a str| {
        map(
            preceded(
                tag("=yend "),
                permutation((
                    parse_keyword("part", tag(part.to_string().as_str())),
                    opt(parse_keyword(
                        "total",
                        tag(total.unwrap_or_default().to_string().as_str()),
                    )),
                    parse_keyword("pcrc32", |s: &'a str| -> IResult<&'a str, u32, E> {
                        let (s, hex) = take_while_m_n(1, 8, |c: char| c.is_ascii_hexdigit())(s)?;
                        Ok((s, u32::from_str_radix(hex, 16).unwrap()))
                    }),
                    parse_keyword("size", tag(size.to_string().as_str())),
                    opt(parse_keyword(
                        "crc32",
                        |s: &'a str| -> IResult<&'a str, u32, E> {
                            let (s, hex) =
                                take_while_m_n(1, 8, |c: char| c.is_ascii_hexdigit())(s)?;
                            Ok((s, u32::from_str_radix(hex, 16).unwrap()))
                        },
                    )),
                )),
            ),
            |(_, _, pcrc32, _, crc32)| (pcrc32, crc32),
        )(s)
    }
}

fn parse_singlepart_yend<'a, E>(size: u64) -> impl Fn(&'a str) -> IResult<&'a str, Option<u32>, E>
where
    E: nom::error::ParseError<&'a str>,
{
    move |s: &'a str| {
        map(
            preceded(
                tag("=yend "),
                permutation((
                    parse_keyword("size", tag(size.to_string().as_str())),
                    opt(parse_keyword(
                        "crc32",
                        |s: &'a str| -> IResult<&'a str, u32, E> {
                            let (s, hex) =
                                take_while_m_n(1, 8, |c: char| c.is_ascii_hexdigit())(s)?;
                            Ok((s, u32::from_str_radix(hex, 16).unwrap()))
                        },
                    )),
                )),
            ),
            |(_, crc32)| crc32,
        )(s)
    }
}

fn parse_keyword<'a, P, O, E>(
    keyword: &'static str,
    mut value_parser: P,
) -> impl FnMut(&'a str) -> IResult<&'a str, O, E>
where
    E: nom::error::ParseError<&'a str>,
    P: Parser<&'a str, O, E>,
{
    move |s: &'a str| {
        let (s, value) = preceded(
            tag(keyword),
            preceded(tag("="), |s: &'a str| value_parser.parse(s)),
        )(s)?;
        // separated_pair(tag(keyword), tag("="), |s: &'a str| value_parser.parse(s))(s)?;
        let (s, _) = cond(keyword == "name", line_ending)(s)?;
        let (s, _) = cond(keyword != "name", alt((multispace1, eof)))(s)?;

        Ok((s, value))
    }
}

// #[derive(Debug, PartialEq, Eq)]
// struct Token<'a, V> {
//     position: &'a str,
//     keyword: &'a str,
//     value: V,
// }

// type &'a str = LocatedSpan<&'a str>;

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use std::io::BufReader;

    use nom::{error::VerboseError, IResult};

    use crate::{
        decode::{
            parse_multipart_yend, parse_ybegin, BeginPartTokens, BeginTokens, FileMetaData,
            PartMetaData,
        },
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
    fn parse_valid_footer_end_nl() {
        let parse_result: IResult<_, _, VerboseError<_>> =
            parse_multipart_yend(26624, 1, None)("=yend size=26624 part=1 pcrc32=ae052b48\n");
        println!("{:?}", parse_result);
        assert!(parse_result.is_ok());

        let (s, (pcrc32, crc32)) = parse_result.unwrap();

        assert!(s.is_empty());
        assert!(crc32.is_none());

        assert_eq!(pcrc32, 0xae052b48);
    }

    #[test]
    fn parse_valid_footer_end_crlf() {
        let parse_result: IResult<_, _, VerboseError<_>> = parse_multipart_yend(26624, 1, None)(
            "=yend size=26624 part=1 pcrc32=ae052b48 crc32=ff00ff00\r\n",
        );
        assert!(parse_result.is_ok());

        let (s, (pcrc32, crc32)) = parse_result.unwrap();

        assert!(s.is_empty());
        assert!(crc32.is_some());

        assert_eq!(pcrc32, 0xae052b48);
        assert_eq!(crc32.unwrap(), 0xff00ff00);
    }

    // #[test]
    // fn parse_valid_footer_end_space() {
    //     let parse_result: IResult<_, _, VerboseError<_>> =
    //         parse_yend(Span::new("=yend size=26624 part=1 pcrc32=ae052b48 \n"));
    //     assert!(parse_result.is_ok());

    //     let (
    //         s,
    //         EndTokens {
    //             size,
    //             part_tokens,
    //             crc32,
    //         },
    //     ) = parse_result.unwrap();

    //     assert!(s.is_empty());
    //     assert_token(size, "size", 26624, 6, 1, "size=26624");
    //     assert!(crc32.is_none());

    //     assert!(part_tokens.is_some());
    //     let EndPartTokens {
    //         pcrc32,
    //         part,
    //         total,
    //     } = part_tokens.unwrap();

    //     assert_token(part, "part", 1, 17, 1, &"part=1");
    //     assert_token(pcrc32, "pcrc32", 0xae052b48, 24, 1, "pcrc32=ae052b48");
    //     assert!(total.is_none());
    // }

    #[test]
    fn parse_valid_header_begin() {
        let parse_result: IResult<_, _, VerboseError<_>> =
            parse_ybegin("=ybegin part=1 line=128 size=189463 name=CatOnKeyboardInSpace001.jpg\n");
        assert!(parse_result.is_ok());

        let (
            s,
            BeginTokens {
                line,
                size,
                part_tokens,
                name,
            },
        ) = parse_result.unwrap();

        assert!(s.is_empty());
        assert_eq!(line, 128);
        assert_eq!(size, 189463);
        assert_eq!(name, "CatOnKeyboardInSpace001.jpg");

        assert!(part_tokens.is_some());
        let BeginPartTokens { part, total } = part_tokens.unwrap();

        assert_eq!(part, 1);
        assert!(total.is_none());
    }

    // #[test]
    // fn parse_valid_header_part() {
    //     let parse_result = parse_keywords(b"=ypart begin=1 end=189463\n");
    //     assert!(parse_result.is_ok());
    //     let metadata = parse_result.unwrap();
    //     assert_eq!(
    //         Some(Keyword {
    //             keyword_start: 7,
    //             value_start: 13,
    //             value: 1,
    //             line_buf: b"=ypart begin=1 end=189463\n"
    //         }),
    //         metadata.begin
    //     );
    //     assert_eq!(
    //         Some(Keyword {
    //             keyword_start: 15,
    //             value_start: 19,
    //             value: 189_463,
    //             line_buf: b"=ypart begin=1 end=189463\n"
    //         }),
    //         metadata.end
    //     );
    // }

    // #[test]
    // fn invalid_header_tag() {
    //     let parse_result = parse_keywords(b"=yparts begin=1 end=189463\n");
    //     assert!(parse_result.is_err());
    // }

    // #[test]
    // fn invalid_header_unknown_keyword() {
    //     let parse_result = parse_keywords(b"=ybegin parts=1 total=4 name=party.jpg\r\n");
    //     assert!(parse_result.is_err());
    // }

    // #[test]
    // fn invalid_header_invalid_begin() {
    //     let parse_result = parse_keywords(b"=ypart begin=a end=189463\n");
    //     assert!(parse_result.is_err());
    // }

    // #[test]
    // fn invalid_header_invalid_end() {
    //     let parse_result = parse_keywords(b"=ypart begin=1 end=18_9463\n");
    //     assert!(parse_result.is_err());
    // }

    // #[test]
    // fn invalid_header_empty_keyword() {
    //     let parse_result = parse_keywords(b"=ypart =1 end=189463\n");
    //     assert!(parse_result.is_err());
    // }

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
