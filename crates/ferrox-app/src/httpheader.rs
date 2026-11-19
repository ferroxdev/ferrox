use crate::conn::Connection;
use std::io::{Read, Write};
use std::time::Instant;

const HEAD_LIMIT: usize = 8192;

#[derive(Debug)]
pub(crate) struct HeadReader<R: Read = Connection> {
    read: R,
    prefix: Vec<u8>,
    at: usize,
}

impl HeadReader<Connection> {
    /// Arm or clear the poll quantum on the handle this reader reads through; a duplicated socket inherits no read timeout on Windows.
    pub(crate) fn set_poll(&mut self, every: Option<std::time::Duration>) {
        let _ = self.read.set_read_timeout(every);
    }
}

impl<R: Read + crate::proxy::RelayPoll> crate::proxy::RelayPoll for HeadReader<R> {
    fn arm_relay_poll(&mut self) {
        self.read.arm_relay_poll();
    }
}

impl<R: Read> HeadReader<R> {
    // A head that ended at the delimiter leaves no tail to deliver, so its buffer is dead at birth.
    fn new(read: R, prefix: Vec<u8>, at: usize) -> Self {
        if at == prefix.len() {
            return Self {
                read,
                prefix: Vec::new(),
                at: 0,
            };
        }
        Self { read, prefix, at }
    }
}

impl<R: Read> Read for HeadReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.at < self.prefix.len() {
            let n = (self.prefix.len() - self.at).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.at..self.at + n]);
            self.at += n;
            if self.at >= self.prefix.len() {
                // The head and the payload that rode with it leave together, once nothing reads them.
                self.prefix = Vec::new();
                self.at = 0;
            }
            return Ok(n);
        }
        self.read.read(buf)
    }
}

/// The head, the octets that arrived with it, and where the head ends: this read consumes what it proves, so bytes pipelined behind the head are already in hand.
fn read_head(stream: &mut Connection) -> Option<(Vec<u8>, usize)> {
    crate::proxy::read_http_head_kept(stream, HEAD_LIMIT, crate::budgets::head_arrival())
}

const DEFAULT_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";

pub(crate) fn accept(
    stream: Connection,
    paths: &[String],
    response: Option<&[u8]>,
) -> Option<(HeadReader, Connection)> {
    let mut read = stream;
    let (head, at) = read_head(&mut read)?;
    check_request(&head[..at], paths)?;
    let Ok(write) = read.try_clone() else {
        return None;
    };
    let mut write = write;
    write.write_all(response.unwrap_or(DEFAULT_RESPONSE)).ok()?;
    Some((HeadReader::new(read, head, at), write))
}

fn check_request(head: &[u8], paths: &[String]) -> Option<()> {
    let path = decode_path(crate::proxy::request_path(head)?)?;
    paths
        .iter()
        .any(|configured| {
            let configured = configured
                .split_once('?')
                .map_or(configured.as_str(), |(base, _)| base);
            decode_path(configured).is_some_and(|configured| configured.as_ref() == path.as_ref())
        })
        .then_some(())
}

/// Decodes the `%XX` escapes the reference's URL parser decodes, leaving `+` as the plus it is in a path.
fn decode_path(path: &str) -> Option<std::borrow::Cow<'_, [u8]>> {
    let bytes = path.as_bytes();
    if !bytes.contains(&b'%') {
        return Some(std::borrow::Cow::Borrowed(bytes));
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while let Some(byte) = bytes.get(at) {
        if *byte != b'%' {
            out.push(*byte);
            at += 1;
            continue;
        }
        let high = (*bytes.get(at + 1)? as char).to_digit(16)?;
        let low = (*bytes.get(at + 2)? as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
        at += 3;
    }
    Some(std::borrow::Cow::Owned(out))
}

// The same accept over halves that cannot peek: the kept read consumes the head, so what rode in behind it is the reader's own prefix.
pub(crate) fn accept_split<R: Read, W: Write>(
    mut read: R,
    mut write: W,
    paths: &[String],
    response: Option<&[u8]>,
) -> Option<(HeadReader<R>, W)> {
    let (head, at) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
    check_request(&head[..at], paths)?;
    write.write_all(response.unwrap_or(DEFAULT_RESPONSE)).ok()?;
    Some((HeadReader::new(read, head, at), write))
}

const BEFORE_PATH: &[u8] = b"GET ";
const BEFORE_HOST: &[u8] = b" HTTP/1.1\r\nHost: ";
const AFTER_HOST: &[u8] = b"\r\n";
const AFTER_HEADERS: &[u8] = b"Connection: keep-alive\r\n\r\n";

// The request is written as the runs it is made of: the socket packs them into one `writev` and the session coalesces them into one record, so no byte is staged in a buffer of its own first.
fn send_request<W: crate::proxy::FrameWrite>(
    write: &mut W,
    host: &str,
    path: &str,
    headers: &[(String, String)],
) -> Option<()> {
    let headers = crate::headers::masked(headers, &[]);
    write
        .write_slices(&[
            BEFORE_PATH,
            path.as_bytes(),
            BEFORE_HOST,
            host.as_bytes(),
            AFTER_HOST,
            headers.as_bytes(),
            AFTER_HEADERS,
        ])
        .then_some(())
}

pub(crate) fn connect(
    stream: Connection,
    host: &str,
    path: &str,
    headers: &[(String, String)],
) -> Option<(HeadReader, Connection)> {
    let mut read = stream;
    send_request(&mut read, host, path, headers)?;
    let (head, at) = read_head(&mut read)?;
    let previous = read.read_timeout().ok().flatten();
    let _ = read.set_read_timeout(Some(crate::budgets::head_arrival()));
    let mut reader = read_response(read, head, at)?;
    reader.set_poll(previous);
    let Ok(write) = reader.read.try_clone() else {
        return None;
    };
    Some((reader, write))
}

fn response_status(head: &[u8]) -> Option<u16> {
    let end = ferrox_core::foxy::line_end(head)?;
    let mut parts = head[..end].split(|byte| *byte == b' ');
    let version = parts.next()?;
    let status = parts.next()?;
    if !version.starts_with(b"HTTP/1.")
        || status.len() != 3
        || !status.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    std::str::from_utf8(status).ok()?.parse().ok()
}

#[derive(Clone, Copy)]
enum Body {
    None,
    Fixed(usize),
    Chunked,
    Close,
}

fn response_body(head: &[u8], status: u16) -> Option<Body> {
    if status == 101 || status == 204 || status == 304 {
        return Some(Body::None);
    }
    let mut length = None;
    let mut chunked = false;
    for line in head.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let (name, value) = line.split_at(colon);
        let value = trim_ows(&value[1..]);
        if name.eq_ignore_ascii_case(b"content-length") {
            let value = std::str::from_utf8(value).ok()?;
            let parsed = value.parse::<usize>().ok()?;
            if length.is_some_and(|held| held != parsed) {
                return None;
            }
            length = Some(parsed);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            chunked = value
                .rsplit(|byte| *byte == b',')
                .next()
                .is_some_and(|token| trim_ows(token).eq_ignore_ascii_case(b"chunked"));
        }
    }
    if chunked {
        Some(Body::Chunked)
    } else if let Some(length) = length {
        Some(Body::Fixed(length))
    } else if (200..300).contains(&status) {
        Some(Body::None)
    } else {
        Some(Body::Close)
    }
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = value {
        if !matches!(*first, b' ' | b'\t') {
            break;
        }
        value = rest;
    }
    while let [rest @ .., last] = value {
        if !matches!(*last, b' ' | b'\t') {
            break;
        }
        value = rest;
    }
    value
}

fn read_response<R: Read>(read: R, head: Vec<u8>, at: usize) -> Option<HeadReader<R>> {
    let mut read = Some(read);
    let mut source: Option<HeadReader<R>> = None;
    let mut head = head;
    let mut at = at;
    let until = Instant::now() + crate::budgets::head_arrival();
    loop {
        let status = response_status(&head[..at])?;
        if (100..200).contains(&status) && status != 101 {
            let mut stream = match source.take() {
                Some(source) => flatten(source, std::mem::take(&mut head), at),
                None => HeadReader::new(read.take()?, std::mem::take(&mut head), at),
            };
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            let (next, next_at) = crate::proxy::read_exact_head(&mut stream, HEAD_LIMIT, left)?;
            head = next;
            at = next_at;
            source = Some(stream);
            continue;
        }
        let body = response_body(&head[..at], status)?;
        let mut reader = match source {
            Some(source) => flatten(source, head, at),
            None => HeadReader::new(read.take()?, head, at),
        };
        let body_until = Instant::now() + crate::budgets::head_arrival();
        skip_body(&mut reader, body, body_until)?;
        return Some(reader);
    }
}

fn flatten<R: Read>(source: HeadReader<R>, mut head: Vec<u8>, at: usize) -> HeadReader<R> {
    if source.at < source.prefix.len() {
        head.extend_from_slice(&source.prefix[source.at..]);
    }
    HeadReader::new(source.read, head, at)
}

fn skip_body<R: Read>(reader: &mut R, body: Body, until: Instant) -> Option<()> {
    match body {
        Body::None => Some(()),
        Body::Fixed(length) => skip_exact(reader, length, until),
        Body::Chunked => skip_chunked(reader, until),
        Body::Close => None,
    }
}

fn read_within<R: Read>(reader: &mut R, buf: &mut [u8], until: Instant) -> Option<()> {
    let mut at = 0;
    while at < buf.len() {
        if Instant::now() >= until {
            return None;
        }
        match reader.read(&mut buf[at..]) {
            Ok(0) => return None,
            Ok(read) => at += read,
            Err(error) if crate::proxy::is_timeout(&error) => {}
            Err(_) => return None,
        }
    }
    Some(())
}

fn skip_exact<R: Read>(reader: &mut R, mut left: usize, until: Instant) -> Option<()> {
    let mut buf = [0u8; 512];
    while left > 0 {
        let take = left.min(buf.len());
        read_within(reader, &mut buf[..take], until)?;
        left -= take;
    }
    Some(())
}

fn skip_chunked<R: Read>(reader: &mut R, until: Instant) -> Option<()> {
    let mut trailers = HEAD_LIMIT;
    loop {
        let line = read_line(reader, until)?;
        let size = trim_ows(line.split(|byte| *byte == b';').next()?);
        let size = usize::from_str_radix(std::str::from_utf8(size).ok()?, 16).ok()?;
        if size == 0 {
            loop {
                let line = read_line(reader, until)?;
                trailers = trailers.checked_sub(line.len() + 2)?;
                if line.is_empty() {
                    return Some(());
                }
            }
        }
        skip_exact(reader, size, until)?;
        let mut crlf = [0u8; 2];
        read_within(reader, &mut crlf, until)?;
        if crlf != *b"\r\n" {
            return None;
        }
    }
}

fn read_line<R: Read>(reader: &mut R, until: Instant) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        read_within(reader, &mut byte, until)?;
        if byte[0] == b'\n' {
            if line.last() != Some(&b'\r') {
                return None;
            }
            line.pop();
            return Some(line);
        }
        if line.len() >= HEAD_LIMIT {
            return None;
        }
        line.push(byte[0]);
    }
}

// The same connect over halves that cannot peek: pipelined bytes arrive as a prefix.
pub(crate) fn connect_split<R: Read + crate::proxy::RelayPoll, W: crate::proxy::FrameWrite>(
    mut read: R,
    mut write: W,
    host: &str,
    path: &str,
    headers: &[(String, String)],
) -> Option<(HeadReader<R>, W)> {
    send_request(&mut write, host, path, headers)?;
    let (head, at) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
    crate::proxy::RelayPoll::arm_head_poll(&mut read);
    let mut reader = read_response(read, head, at)?;
    crate::proxy::RelayPoll::arm_relay_poll(&mut reader);
    Some((reader, write))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn any_configured_path_is_accepted() {
        let head = b"GET /two HTTP/1.1\r\nHost: h\r\n\r\n";
        let paths = ["/one".to_owned(), "/two".to_owned()];
        assert!(check_request(head, &paths).is_some());
        assert!(check_request(head, &["/one".to_owned()]).is_none());
        assert!(check_request(head, &["/two?x=1".to_owned()]).is_some());
    }

    #[test]
    fn header_carries_an_echo_over_loopback() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, mut write) =
                accept(stream, &["/camouflage".to_owned()], None).expect("headers");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            write.write_all(b"pong").expect("writes");
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut write) =
            connect(stream, "oracle.example", "/camouflage", &[]).expect("headers");
        write.write_all(b"ping").expect("writes");
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

    #[test]
    fn a_configured_header_reaches_the_camouflage_request() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).expect("reads");
                head.push(byte[0]);
            }
            let text = String::from_utf8(head).expect("utf8");
            assert!(text.contains("X-Custom: 1\r\n"), "{text}");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
                .expect("writes");
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let headers = vec![("X-Custom".to_owned(), "1".to_owned())];
        connect(stream, "oracle.example", "/camouflage", &headers).expect("headers");
        server.join().expect("joins");
    }

    #[test]
    fn a_custom_204_response_is_accepted() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).expect("reads");
                head.push(byte[0]);
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .expect("writes");
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        connect(stream, "oracle.example", "/camouflage", &[]).expect("accepts the response");
        server.join().expect("joins");
    }

    #[test]
    fn an_interim_head_is_not_the_camouflage_answer() {
        struct Sink(Vec<u8>);
        impl Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl crate::proxy::FrameWrite for Sink {
            fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
                for part in parts {
                    self.0.extend_from_slice(part);
                }
                true
            }
        }
        let response = b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 200 OK\r\n\r\nping";
        let (mut reader, _write) = connect_split(
            std::io::Cursor::new(response.to_vec()),
            Sink(Vec::new()),
            "oracle.example",
            "/camouflage",
            &[],
        )
        .expect("accepts the final response");
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads the payload");
        assert_eq!(&buf, b"ping");
    }

    #[test]
    fn a_configured_response_is_the_one_the_carrier_sends() {
        let head = b"GET /camouflage HTTP/1.1\r\nHost: h\r\n\r\n";
        let response = b"HTTP/1.1 204 No Content\r\nX-Camo: 1\r\n\r\n";
        let (_reader, writer) = accept_split(
            std::io::Cursor::new(head),
            Vec::new(),
            &["/camouflage".to_owned()],
            Some(response),
        )
        .expect("answers");
        assert_eq!(writer, response);
    }

    /// The record arm takes the buffer its own head read filled, head octets and all: what rode behind the delimiter is handed over inside it, not copied into a second owner.
    #[test]
    fn the_record_head_hands_over_the_buffer_it_filled() {
        const HEAD: &[u8] = b"GET /camouflage HTTP/1.1\r\nHost: h\r\n\r\n";
        const TAIL: &[u8] = b"ping";
        let mut wire = Vec::from(HEAD);
        wire.extend_from_slice(TAIL);
        let (reader, _write) = accept_split(
            std::io::Cursor::new(wire),
            Vec::new(),
            &["/camouflage".to_owned()],
            None,
        )
        .expect("answers");
        assert_eq!(reader.at, HEAD.len(), "the cursor sits past the head");
        assert_eq!(
            reader.prefix.len(),
            HEAD.len() + TAIL.len(),
            "one buffer carries the request and what rode behind it"
        );
        assert_eq!(
            reader.prefix[reader.at..].as_ptr() as usize - reader.prefix.as_ptr() as usize,
            reader.at,
            "and those bytes lie inside the allocation the head read made"
        );
    }

    /// The kept head hands its own buffer to the reader with the head already walked past: the bytes behind it are delivered from that buffer and the reader never reaches the socket; once the walk finishes, the buffer that carried the head is released rather than held for the connection's life.
    #[test]
    fn the_bytes_behind_the_head_reach_the_relay_without_a_syscall() {
        const HEAD: &[u8] = b"GET /camouflage HTTP/1.1\r\nHost: h\r\n\r\n";
        struct Refused;
        impl Read for Refused {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                panic!("the head's tail is already in hand")
            }
        }
        let mut prefix = Vec::from(HEAD);
        prefix.extend_from_slice(b"ping");
        let mut reader = HeadReader::new(Refused, prefix, HEAD.len());
        let mut got = [0u8; 4];
        assert_eq!(reader.read(&mut got).expect("delivers"), 4);
        assert_eq!(&got, b"ping", "the bytes behind the head, not a re-read");
        assert_eq!(
            reader.prefix.capacity(),
            0,
            "the read that finished the walk released the buffer that carried the head"
        );

        // The ordinary shape: the head ends at the delimiter, so nothing is left to deliver and the buffer is dead at birth.
        let mut reader = HeadReader::new(
            std::io::Cursor::new(b"nextnext"),
            Vec::from(HEAD),
            HEAD.len(),
        );
        let mut got = [0u8; 4];
        for _ in 0..2 {
            assert_eq!(reader.read(&mut got).expect("reaches the socket"), 4);
            assert_eq!(&got, b"next");
            assert_eq!(
                reader.prefix.capacity(),
                0,
                "a head with no tail holds no buffer across the reads that follow"
            );
        }
    }

    /// The camouflage request reaches the write as the runs it is made of: the path and host octets go over where they lie, so the handshake stages no copy of itself.
    #[test]
    fn the_request_reaches_the_write_as_the_runs_it_is_made_of() {
        #[derive(Default)]
        struct Runs {
            calls: usize,
            segments: Vec<(usize, usize)>,
            bytes: Vec<u8>,
        }

        impl Write for Runs {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.segments.push((buf.as_ptr() as usize, buf.len()));
                self.bytes.extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl crate::proxy::FrameWrite for Runs {
            fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
                self.calls += 1;
                for part in parts {
                    self.segments.push((part.as_ptr() as usize, part.len()));
                    self.bytes.extend_from_slice(part);
                }
                true
            }
        }

        const ANSWER: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n";
        // One binding each, so the pointer the callee was handed is the pointer the gate asserts.
        let host = "oracle.example";
        let path = "/camouflage";
        let (_reader, write) = connect_split(
            std::io::Cursor::new(Vec::from(ANSWER)),
            Runs::default(),
            host,
            path,
            &[],
        )
        .expect("answers");
        assert_eq!(
            write.bytes,
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n")
                .as_bytes(),
            "the bytes the removed formatter wrote"
        );
        let lengths: Vec<usize> = write.segments.iter().map(|(_, len)| *len).collect();
        assert_eq!(
            lengths,
            [
                BEFORE_PATH.len(),
                path.len(),
                BEFORE_HOST.len(),
                host.len(),
                AFTER_HOST.len(),
                0,
                AFTER_HEADERS.len()
            ],
            "one run per piece, gathered rather than staged"
        );
        assert_eq!(
            write.segments[1].0,
            path.as_ptr() as usize,
            "the path's own octets, not a copy of them"
        );
        assert_eq!(
            write.segments[3].0,
            host.as_ptr() as usize,
            "and the host's own"
        );
        assert_eq!(write.calls, 1, "one gathered call carries every run");
    }

    #[test]
    fn the_request_target_is_a_borrow_and_ignores_the_query() {
        assert_eq!(
            crate::proxy::request_path(b"GET /camouflage HTTP/1.1\r\nHost: h\r\n\r\n"),
            Some("/camouflage")
        );
        assert_eq!(
            crate::proxy::request_path(b"GET /camouflage?t=17 HTTP/1.1\r\n\r\n"),
            Some("/camouflage")
        );
        assert_eq!(
            crate::proxy::request_path(b"POST /camouflage HTTP/1.1\r\n\r\n"),
            None
        );
        assert_eq!(crate::proxy::request_path(b"GET\r\n\r\n"), None);
        assert_eq!(crate::proxy::request_path(&[0xff, 0xfe, 0xfd]), None);
        assert_eq!(
            crate::proxy::request_path(b"GET /camouflage HTTP/1.1\r\n\r\n"),
            Some("/camouflage"),
            "and the bytes it points at are the head's, not a copy"
        );
    }

    #[test]
    fn a_configured_non_success_status_is_a_valid_camouflage_response() {
        assert_eq!(
            response_status(b"HTTP/1.1 404 Not Found\r\n\r\n"),
            Some(404)
        );
        assert_eq!(
            response_status(b"HTTP/1.0 204 No Content\r\n\r\n"),
            Some(204)
        );
        assert_eq!(response_status(b"HTTP/2 200 OK\r\n\r\n"), None);
        assert_eq!(response_status(b"HTTP/1.1 20 OK\r\n\r\n"), None);
    }

    #[test]
    fn a_percent_escaped_path_matches_the_configured_path_and_plus_stays_plus() {
        let paths = [
            "/two/part".to_owned(),
            "/two+part".to_owned(),
            "/two%2Fpart".to_owned(),
        ];
        assert!(check_request(b"GET /two%2Fpart HTTP/1.1\r\nHost: h\r\n\r\n", &paths).is_some());
        assert!(check_request(b"GET /two/part HTTP/1.1\r\nHost: h\r\n\r\n", &paths).is_some());
        assert!(check_request(b"GET /two+part HTTP/1.1\r\nHost: h\r\n\r\n", &paths).is_some());
        assert!(check_request(
            b"GET /two%20part HTTP/1.1\r\nHost: h\r\n\r\n",
            &["/two part".to_owned()]
        )
        .is_some());
        assert!(check_request(b"GET /two%zzpart HTTP/1.1\r\nHost: h\r\n\r\n", &paths).is_none());
    }

    #[test]
    fn a_framed_response_body_is_consumed_before_the_tunnel_bytes() {
        let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n\r\nerrornext";
        let (mut reader, _write) = connect_split(
            std::io::Cursor::new(Vec::from(&response[..])),
            Vec::new(),
            "oracle.example",
            "/camouflage",
            &[],
        )
        .expect("answers");
        let mut got = [0u8; 4];
        reader.read_exact(&mut got).expect("reads");
        assert_eq!(&got, b"next");
    }

    #[test]
    fn an_unframed_error_body_is_not_tunnel_traffic() {
        let response = b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nerror";
        assert!(connect_split(
            std::io::Cursor::new(Vec::from(&response[..])),
            Vec::new(),
            "oracle.example",
            "/camouflage",
            &[],
        )
        .is_none());
    }

    #[test]
    fn a_chunked_response_body_is_consumed_before_the_tunnel_bytes() {
        let response =
            b"HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nerror\r\n0\r\n\r\nnext";
        let (mut reader, _write) = connect_split(
            std::io::Cursor::new(Vec::from(&response[..])),
            Vec::new(),
            "oracle.example",
            "/camouflage",
            &[],
        )
        .expect("answers");
        let mut got = [0u8; 4];
        reader.read_exact(&mut got).expect("reads");
        assert_eq!(&got, b"next");
    }

    #[test]
    fn an_interim_response_is_read_through_to_the_final_head() {
        let response =
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nnext";
        let (mut reader, _write) = connect_split(
            std::io::Cursor::new(Vec::from(&response[..])),
            Vec::new(),
            "oracle.example",
            "/camouflage",
            &[],
        )
        .expect("answers");
        let mut got = [0u8; 4];
        reader.read_exact(&mut got).expect("reads");
        assert_eq!(&got, b"next");
    }

    #[test]
    fn two_interim_responses_keep_the_final_head_and_tunnel_bytes() {
        let response = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nnext";
        let (mut reader, _write) = connect_split(
            std::io::Cursor::new(Vec::from(&response[..])),
            Vec::new(),
            "oracle.example",
            "/camouflage",
            &[],
        )
        .expect("answers");
        let mut got = [0u8; 4];
        reader.read_exact(&mut got).expect("reads");
        assert_eq!(&got, b"next");
    }

    #[test]
    fn header_rejects_a_wrong_path() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, &["/camouflage".to_owned()], None).is_none());
        });
        let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /other HTTP/1.1\r\nHost: h\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }
}
