//! Bounded framing for the local adapter protocol:
//! a 4-byte big-endian length followed by that many bytes of canonical JSON.
//! Frames larger than the negotiated maximum are rejected before any payload
//! is buffered, so a misbehaving peer cannot force unbounded allocation.

use crate::error::{DecodeError, ErrorClass};
use std::io::{self, Read, Write};

pub const DEFAULT_MAX_FRAME: u32 = 1 << 20;

#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    /// Clean end of stream at a frame boundary.
    Eof,
    TooLarge(u32),
    /// Stream ended inside a frame.
    Truncated,
}

impl From<FrameError> for DecodeError {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::TooLarge(n) => {
                DecodeError::new(ErrorClass::FrameTooLarge, "$", format!("frame of {n} bytes exceeds limit"))
            }
            other => DecodeError::new(ErrorClass::Syntax, "$", format!("{other:?}")),
        }
    }
}

pub fn write_frame(w: &mut impl Write, payload: &[u8], max: u32) -> Result<(), FrameError> {
    let n = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
    if n > max {
        return Err(FrameError::TooLarge(n));
    }
    w.write_all(&n.to_be_bytes()).map_err(FrameError::Io)?;
    w.write_all(payload).map_err(FrameError::Io)?;
    w.flush().map_err(FrameError::Io)
}

pub fn read_frame(r: &mut impl Read, max: u32) -> Result<Vec<u8>, FrameError> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Err(FrameError::Eof),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(k) => got += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(FrameError::Io(e)),
        }
    }
    let n = u32::from_be_bytes(len);
    if n > max {
        return Err(FrameError::TooLarge(n));
    }
    let mut buf = vec![0u8; n as usize];
    r.read_exact(&mut buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof { FrameError::Truncated } else { FrameError::Io(e) }
    })?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_bounds() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"a\":1}", 64).unwrap();
        write_frame(&mut buf, b"[]", 64).unwrap();
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r, 64).unwrap(), b"{\"a\":1}");
        assert_eq!(read_frame(&mut r, 64).unwrap(), b"[]");
        assert!(matches!(read_frame(&mut r, 64), Err(FrameError::Eof)));
        assert!(matches!(write_frame(&mut Vec::new(), &[0; 65], 64), Err(FrameError::TooLarge(65))));
        // A header announcing 4 GiB is rejected without allocating it.
        let mut r = &[0xff, 0xff, 0xff, 0xff, 1][..];
        assert!(matches!(read_frame(&mut r, 64), Err(FrameError::TooLarge(_))));
        let mut r = &[0, 0, 0, 5, b'a'][..];
        assert!(matches!(read_frame(&mut r, 64), Err(FrameError::Truncated)));
    }
}
