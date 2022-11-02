use std::convert::From;
use std::fmt;
use std::io;

use nom::error::VerboseError;
use nom::Err;
use nom::Offset;

/// Error enum for errors that can be encountered while decoding.
#[derive(Debug)]
pub enum DecodeError {
    /// Fewer or more bytes than expected.
    IncompleteData {
        /// the expected size, as specified in the yenc header
        expected_size: u64,
        /// the actual size, as found while reading
        actual_size: u64,
    },
    /// The header or footer line contains unexpected characters or is incomplete.
    InvalidHeader {
        /// the header line
        line: String,
        /// the position in the line where the parsing error occurred
        position: usize,
    },
    /// CRC32 checksum of the part is not the expected checksum.
    InvalidChecksum,
    /// An I/O error occurred.
    IoError(io::Error),
}

/// Error enum for errors that can be encountered when validating the encode options or while encoding.
#[derive(Debug)]
pub enum EncodeError {
    /// Multiple parts (parts > 1), but no part number specified
    PartNumberMissing,
    /// Multiple parts (parts > 1), but no begin offset specified
    PartBeginOffsetMissing,
    /// Multiple parts (parts > 1), but no end offset specified
    PartEndOffsetMissing,
    /// Multiple parts (parts > 1), and begin offset larger than end offset
    PartOffsetsInvalidRange,
    /// I/O Error
    IoError(io::Error),
}

impl<I> From<(I, Err<VerboseError<I>>)> for DecodeError
where
    I: core::ops::Deref<Target = str>,
{
    fn from((i, e): (I, Err<VerboseError<I>>)) -> Self {
        match e {
            nom::Err::Error(e) => (i, e).into(),
            _ => unreachable!(),
        }
    }
}

impl<I> From<(I, VerboseError<I>)> for DecodeError
where
    I: core::ops::Deref<Target = str>,
{
    fn from((input, e): (I, VerboseError<I>)) -> Self {
        for (substring, _) in e.errors.iter() {
            let offset = input.offset(substring);

            if input.is_empty() {
                return DecodeError::InvalidHeader {
                    line: input.to_string(),
                    position: 0,
                };
            } else {
                let prefix = &input.as_bytes()[..offset];

                // Find the line that includes the subslice:
                // Find the *last* newline before the substring starts
                let line_begin = prefix
                    .iter()
                    .rev()
                    .position(|&b| b == b'\n')
                    .map(|pos| offset - pos)
                    .unwrap_or(0);

                // Find the full line after that newline
                let line = input[line_begin..]
                    .lines()
                    .next()
                    .unwrap_or(&input[line_begin..])
                    .trim_end();

                // The (1-indexed) column number is the offset of our substring into that line
                let position = line.offset(substring) + 1;

                return DecodeError::InvalidHeader {
                    line: line.to_string(),
                    position,
                };
            }
        }

        return DecodeError::InvalidHeader {
            line: input.to_string(),
            position: 0,
        };
    }
}

impl From<io::Error> for DecodeError {
    fn from(error: io::Error) -> DecodeError {
        DecodeError::IoError(error)
    }
}

impl From<io::Error> for EncodeError {
    fn from(error: io::Error) -> EncodeError {
        EncodeError::IoError(error)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DecodeError::IncompleteData {
                ref expected_size,
                ref actual_size,
            } => write!(
                f,
                "Incomplete data: expected size {}, actual size {}",
                expected_size, actual_size
            ),
            DecodeError::InvalidHeader { ref line, position } => {
                write!(f, "Invalid header: \n{}\n{}^", line, " ".repeat(position))
            }
            DecodeError::InvalidChecksum => write!(f, "Invalid checksum"),
            DecodeError::IoError(ref err) => write!(f, "I/O error {}", err),
        }
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            EncodeError::PartNumberMissing => {
                write!(f, "Multiple parts, but no part number specified.")
            }
            EncodeError::PartBeginOffsetMissing => {
                write!(f, "Multiple parts, but no begin offset specified.")
            }
            EncodeError::PartEndOffsetMissing => {
                write!(f, "Multiple parts, but no end offset specified.")
            }
            EncodeError::PartOffsetsInvalidRange => {
                write!(f, "Multiple parts, begin offset larger than end offset")
            }
            EncodeError::IoError(ref err) => write!(f, "I/O error {}", err),
        }
    }
}
// impl error::Error for DecodeError {}
