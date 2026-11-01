//! The little DER that a CMS signature needs: a writer, and a reader for elements with single-byte tags.
//!
//! Nothing here is a general ASN.1 library. The writer builds the few structures of a `SignedData` (definite lengths, so
//! DER and BER agree), and the reader walks a certificate far enough to find its issuer, serial number and public key.
//! Every read is checked: bytes that are not DER are `None`, never a panic.

/// `SEQUENCE`.
pub(crate) const SEQUENCE: u8 = 0x30;
/// `SET`.
pub(crate) const SET: u8 = 0x31;
/// `INTEGER`.
pub(crate) const INTEGER: u8 = 0x02;
/// `BIT STRING`.
pub(crate) const BIT_STRING: u8 = 0x03;
/// `OCTET STRING`.
pub(crate) const OCTET_STRING: u8 = 0x04;
/// `NULL`.
pub(crate) const NULL: u8 = 0x05;
/// `OBJECT IDENTIFIER`.
pub(crate) const OID: u8 = 0x06;
/// `UTF8String`.
#[cfg(any(test, feature = "testing"))]
pub(crate) const UTF8_STRING: u8 = 0x0C;
/// `UTCTime`.
pub(crate) const UTC_TIME: u8 = 0x17;
/// `GeneralizedTime`.
pub(crate) const GENERALIZED_TIME: u8 = 0x18;
/// `[0]` constructed, context-specific: explicit tags and implicit sets.
pub(crate) const CONTEXT_0: u8 = 0xA0;

/// The encoding of `tag`, the length of `content` and `content`.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len().saturating_add(6));
    out.push(tag);
    push_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// The parts one after the other.
pub(crate) fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.iter().flat_map(|part| part.iter().copied()).collect()
}

/// An `OBJECT IDENTIFIER` with the encoded arcs `arcs` (the content, without tag and length).
pub(crate) fn oid(arcs: &[u8]) -> Vec<u8> {
    tlv(OID, arcs)
}

/// `NULL`, the parameters of the RSA algorithm identifiers.
pub(crate) fn null() -> Vec<u8> {
    vec![NULL, 0]
}

/// An `INTEGER` with a small non-negative value.
pub(crate) fn small_integer(value: u8) -> Vec<u8> {
    // Values of a byte with the high bit set need a leading zero to stay positive.
    if value >= 0x80 {
        tlv(INTEGER, &[0, value])
    } else {
        tlv(INTEGER, &[value])
    }
}

fn push_length(out: &mut Vec<u8>, length: usize) {
    if let Ok(short) = u8::try_from(length)
        && short < 0x80
    {
        out.push(short);
        return;
    }
    let bytes: Vec<u8> = length.to_be_bytes().into_iter().skip_while(|byte| *byte == 0).collect();
    // A `usize` has at most eight bytes.
    out.push(0x80 | u8::try_from(bytes.len()).unwrap_or(8));
    out.extend_from_slice(&bytes);
}

/// One element read from DER.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Element<'a> {
    /// The tag byte.
    pub(crate) tag: u8,
    /// What the element holds.
    pub(crate) content: &'a [u8],
    /// The whole element: tag, length and content.
    pub(crate) encoded: &'a [u8],
}

/// Reads the elements one after the other from `data`; ends at the first byte that is not an element.
#[derive(Debug, Clone)]
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `data`.
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { rest: data }
    }

    /// Whether everything was read.
    pub(crate) const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Element<'a>;

    fn next(&mut self) -> Option<Element<'a>> {
        let (element, rest) = read(self.rest)?;
        self.rest = rest;
        Some(element)
    }
}

/// The first element of `data` and what follows it.
fn read(data: &[u8]) -> Option<(Element<'_>, &[u8])> {
    let tag = *data.first()?;
    // Long-form tags (the low five bits all set) do not occur in what is read here.
    if tag & 0x1F == 0x1F {
        return None;
    }
    let first = *data.get(1)?;
    let (length, header) = if first < 0x80 {
        (usize::from(first), 2_usize)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 4 {
            return None;
        }
        let bytes = data.get(2..2 + count)?;
        let length = bytes
            .iter()
            .fold(0_usize, |value, byte| (value << 8) | usize::from(*byte));
        (length, 2 + count)
    };
    let end = header.checked_add(length)?;
    let element = Element {
        tag,
        content: data.get(header..end)?,
        encoded: data.get(..end)?,
    };
    Some((element, data.get(end..)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_use_the_short_form_below_128_and_the_long_form_above() {
        assert_eq!(tlv(OCTET_STRING, &[1, 2, 3]), [0x04, 3, 1, 2, 3]);
        let medium = tlv(OCTET_STRING, &[7; 200]);
        assert_eq!(medium.get(..3), Some(&[0x04, 0x81, 200][..]));
        let long = tlv(OCTET_STRING, &vec![7; 70_000]);
        assert_eq!(long.get(..5), Some(&[0x04, 0x83, 0x01, 0x11, 0x70][..]));
        assert_eq!(long.len(), 5 + 70_000);
    }

    #[test]
    fn what_is_written_is_read_back() {
        for length in [0, 1, 127, 128, 255, 256, 70_000] {
            let content = vec![0xAB; length];
            let bytes = tlv(SEQUENCE, &content);
            let mut reader = Reader::new(&bytes);
            let element = reader.next().unwrap();
            assert_eq!(element.tag, SEQUENCE);
            assert_eq!(element.content, content.as_slice());
            assert_eq!(element.encoded, bytes.as_slice());
            assert!(reader.is_empty() && reader.next().is_none());
        }
    }

    #[test]
    fn elements_follow_each_other() {
        let bytes = concat(&[&small_integer(1), &small_integer(200), &null()]);
        let tags: Vec<(u8, Vec<u8>)> = Reader::new(&bytes)
            .map(|element| (element.tag, element.content.to_vec()))
            .collect();
        assert_eq!(tags, [(INTEGER, vec![1]), (INTEGER, vec![0, 200]), (NULL, vec![])]);
    }

    #[test]
    fn bytes_that_are_not_der_are_nothing_and_never_a_panic() {
        for bytes in [
            &[][..],
            &[0x30][..],
            &[0x30, 0x05, 1, 2][..],
            &[0x30, 0x80][..],
            &[0x30, 0x85, 0, 0, 0, 0, 1][..],
            &[0x1F, 0x01, 0x00][..],
            &[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF][..],
        ] {
            assert!(Reader::new(bytes).next().is_none(), "{bytes:?}");
        }
    }
}
