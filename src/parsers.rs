use nom::{
    branch::{alt, permutation},
    bytes::complete::{tag, take_until, take_while_m_n},
    character::complete::{line_ending, multispace1, u16, u32, u64},
    combinator::{cond, eof, map, opt, verify},
    error::ParseError,
    sequence::preceded,
    IResult, Parser,
};

use crate::decode::{BeginInfo, PartInfo};

pub fn ybegin<'a, E>(s: &'a str) -> IResult<&'a str, BeginInfo<'a>, E>
where
    E: nom::error::ParseError<&'a str>,
{
    map(
        preceded(
            tag("=ybegin "),
            permutation((
                keyword("line", u16),
                keyword("size", u64),
                map(
                    opt(permutation((
                        keyword("part", u32),
                        opt(keyword("total", u32)),
                    ))),
                    |part_tokens| part_tokens.map(|(part, total)| PartInfo { part, total }),
                ),
                keyword("name", |s: &'a str| -> IResult<&'a str, &'a str, E> {
                    let (s, value) = take_until("\n")(s)?;
                    Ok((s, value))
                }),
            )),
        ),
        |(line, size, part_tokens, name)| BeginInfo {
            line,
            size,
            part_tokens,
            name,
        },
    )(s)
}

pub fn ypart<'a, E>(s: &'a str) -> IResult<&'a str, (u64, u64), E>
where
    E: nom::error::ParseError<&'a str>,
{
    preceded(
        tag("=ypart "),
        permutation((keyword("begin", u64), keyword("end", u64))),
    )(s)
}

pub fn multipart_yend<'a, E>(
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
                    verify(keyword("part", u32), |p: &u32| *p == part),
                    verify(opt(keyword("total", u32)), |t: &Option<u32>| t == &total),
                    keyword("pcrc32", hex),
                    verify(keyword("size", u64), |s: &u64| *s == size),
                    opt(keyword("crc32", hex)),
                )),
            ),
            |(_, _, pcrc32, _, crc32)| (pcrc32, crc32),
        )(s)
    }
}

pub fn singlepart_yend<'a, E>(size: u64) -> impl Fn(&'a str) -> IResult<&'a str, Option<u32>, E>
where
    E: nom::error::ParseError<&'a str>,
{
    move |s: &'a str| {
        map(
            preceded(
                tag("=yend "),
                permutation((
                    verify(keyword("size", u64), |s: &u64| *s == size),
                    opt(keyword("crc32", hex)),
                )),
            ),
            |(_, crc32)| crc32,
        )(s)
    }
}

fn keyword<'a, P, O, E>(
    keyword: &'static str,
    mut value: P,
) -> impl FnMut(&'a str) -> IResult<&'a str, O, E>
where
    E: nom::error::ParseError<&'a str>,
    P: Parser<&'a str, O, E>,
{
    move |s: &'a str| {
        let (s, value) = preceded(
            tag(keyword),
            preceded(tag("="), |s: &'a str| value.parse(s)),
        )(s)?;

        let (s, _) = cond(keyword == "name", line_ending)(s)?;
        let (s, _) = cond(keyword != "name", alt((multispace1, eof)))(s)?;

        Ok((s, value))
    }
}

fn hex<'a, E>(s: &'a str) -> IResult<&'a str, u32, E>
where
    E: ParseError<&'a str>,
{
    let (s, hex) = take_while_m_n(1, 8, |c: char| c.is_ascii_hexdigit())(s)?;
    Ok((s, u32::from_str_radix(hex, 16).unwrap()))
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use nom::{error::VerboseError, IResult};

    use crate::{
        decode::{BeginInfo, PartInfo},
        parsers::{multipart_yend, ybegin, ypart},
    };

    #[test]
    fn parse_valid_footer_end_nl() {
        let parse_result: IResult<_, _, VerboseError<_>> =
            multipart_yend(26624, 1, None)("=yend size=26624 part=1 pcrc32=ae052b48\n");
        println!("{:?}", parse_result);
        assert!(parse_result.is_ok());

        let (s, (pcrc32, crc32)) = parse_result.unwrap();

        assert!(s.is_empty());
        assert!(crc32.is_none());

        assert_eq!(pcrc32, 0xae052b48);
    }

    #[test]
    fn parse_valid_footer_end_crlf() {
        let parse_result: IResult<_, _, VerboseError<_>> = multipart_yend(26624, 1, None)(
            "=yend size=26624 part=1 pcrc32=ae052b48 crc32=ff00ff00\r\n",
        );
        assert!(parse_result.is_ok());

        let (s, (pcrc32, crc32)) = parse_result.unwrap();

        assert!(s.is_empty());
        assert!(crc32.is_some());

        assert_eq!(pcrc32, 0xae052b48);
        assert_eq!(crc32.unwrap(), 0xff00ff00);
    }

    #[test]
    fn parse_valid_footer_end_space() {
        let parse_result: IResult<_, _, VerboseError<_>> =
            multipart_yend(26624, 1, None)("=yend size=26624 part=1 pcrc32=ae052b48 \n");
        assert!(parse_result.is_ok());

        let (s, (pcrc32, crc32)) = parse_result.unwrap();

        assert!(s.is_empty());
        assert!(crc32.is_none());

        assert_eq!(pcrc32, 0xae052b48);
    }

    #[test]
    fn parse_valid_header_begin() {
        let parse_result: IResult<_, _, VerboseError<_>> =
            ybegin("=ybegin part=1 line=128 size=189463 name=CatOnKeyboardInSpace001.jpg\n");
        assert!(parse_result.is_ok());

        let (
            s,
            BeginInfo {
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
        let PartInfo { part, total } = part_tokens.unwrap();

        assert_eq!(part, 1);
        assert!(total.is_none());
    }

    #[test]
    fn parse_valid_header_part() {
        let parse_result: IResult<_, _, VerboseError<_>> = ypart("=ypart begin=1 end=189463\n");
        assert!(parse_result.is_ok());
        let (_, (begin, end)) = parse_result.unwrap();
        assert_eq!(1, begin);
        assert_eq!(189463, end);
    }

    #[test]
    fn invalid_header_tag() {
        let parse_result: IResult<_, _, VerboseError<_>> = ybegin("=yparts begin=1 end=189463\n");
        assert!(parse_result.is_err());
    }

    #[test]
    fn invalid_header_unknown_keyword() {
        let parse_result: IResult<_, _, VerboseError<_>> =
            ybegin("=ybegin parts=1 total=4 name=party.jpg\r\n");
        assert!(parse_result.is_err());
    }

    #[test]
    fn invalid_header_invalid_begin() {
        let parse_result: IResult<_, _, VerboseError<_>> = ypart("=ypart begin=a end=189463\n");
        assert!(parse_result.is_err());
    }

    #[test]
    fn invalid_header_invalid_end() {
        let parse_result: IResult<_, _, VerboseError<_>> = ypart("=ypart begin=1 end=18_9463\n");
        assert!(parse_result.is_err());
    }
}
