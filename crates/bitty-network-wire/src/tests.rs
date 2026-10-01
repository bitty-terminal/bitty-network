//! Codec unit tests: round-trips, fail-closed decoding, and limit boundaries.

use super::*;

fn sample_request() -> Message {
    Message::HttpRequest {
        id: 7,
        plugin_id: "weather".to_owned(),
        grant: Grant {
            hosts: vec![
                GrantHost {
                    host: "api.example.com".to_owned(),
                    ports: vec![443, 8443],
                },
                GrantHost {
                    host: "cdn.example.com".to_owned(),
                    ports: Vec::new(),
                },
            ],
            methods: Some(Method::mask_of([Method::Get, Method::Post])),
        },
        method: Method::Post,
        url: "https://api.example.com/v1?q=1".to_owned(),
        headers: vec![
            ("Accept".to_owned(), "application/json".to_owned()),
            ("X-Empty".to_owned(), String::new()),
        ],
        timeout_ms: 5_000,
        max_body_bytes: 1024,
        body_follows: true,
    }
}

fn all_messages() -> Vec<Message> {
    let mut messages = vec![
        Message::Hello {
            min: 1,
            max: 3,
            component: "net".to_owned(),
            version: "0.1.0".to_owned(),
        },
        Message::HelloAck {
            protocol: PROTOCOL_VERSION,
            component: "net".to_owned(),
            version: "0.1.0".to_owned(),
        },
        sample_request(),
        Message::HttpRequest {
            id: u64::MAX,
            plugin_id: String::new(),
            grant: Grant::default(),
            method: Method::Get,
            url: "http://x/".to_owned(),
            headers: Vec::new(),
            timeout_ms: 0,
            max_body_bytes: 0,
            body_follows: false,
        },
        Message::RequestBody {
            id: 7,
            data: vec![0, 1, 2, 255],
            last: false,
        },
        Message::RequestBody {
            id: 7,
            data: Vec::new(),
            last: true,
        },
        Message::ResponseHead {
            id: 7,
            status: 204,
            headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
        },
        Message::ResponseBody {
            id: 7,
            data: b"hello".to_vec(),
            last: true,
        },
        Message::Error {
            id: CONNECTION_ID,
            kind: ErrorKind::Protocol,
            message: "handshake required".to_owned(),
        },
        Message::Cancel { id: 9 },
        Message::Shutdown,
    ];
    for kind in ErrorKind::ALL {
        messages.push(Message::Error {
            id: 3,
            kind,
            message: kind.as_str().to_owned(),
        });
    }
    for method in Method::ALL {
        messages.push(Message::HttpRequest {
            id: 1,
            plugin_id: "p".to_owned(),
            grant: Grant {
                hosts: Vec::new(),
                methods: Some(method.bit()),
            },
            method,
            url: "https://h/".to_owned(),
            headers: Vec::new(),
            timeout_ms: 1,
            max_body_bytes: 1,
            body_follows: false,
        });
    }
    messages
}

fn str_field(value: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(value.len())
        .expect("test length fits u32")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(value);
    out
}

#[test]
fn every_message_round_trips() {
    for message in all_messages() {
        let payload = encode(&message).expect("encode");
        assert_eq!(payload[0], message.tag());
        assert_eq!(decode(&payload).expect("decode"), message, "{message:?}");
        let frame = encode_frame(&message).expect("frame");
        let (decoded, used) = try_decode_frame(&frame)
            .expect("frame decode")
            .expect("full");
        assert_eq!(decoded, message);
        assert_eq!(used, frame.len());
    }
}

#[test]
fn tag_values_are_fixed() {
    assert_eq!(TAG_HELLO, 0x01);
    assert_eq!(TAG_HELLO_ACK, 0x02);
    assert_eq!(TAG_HTTP_REQUEST, 0x10);
    assert_eq!(TAG_REQUEST_BODY, 0x11);
    assert_eq!(TAG_RESPONSE_HEAD, 0x20);
    assert_eq!(TAG_RESPONSE_BODY, 0x21);
    assert_eq!(TAG_ERROR, 0x2F);
    assert_eq!(TAG_CANCEL, 0x30);
    assert_eq!(TAG_SHUTDOWN, 0x3F);
    assert_eq!(PROTOCOL_VERSION, 1);
    assert_eq!(MAX_FRAME_BYTES, 262_144);
    assert_eq!(MAX_BODY_CHUNK_BYTES, 196_608);
    assert_eq!(MAX_IN_FLIGHT, 64);
}

#[test]
fn byte_layout_is_pinned() {
    let payload = encode(&Message::Cancel { id: 0x0102 }).expect("encode");
    assert_eq!(payload, [0x30, 0, 0, 0, 0, 0, 0, 0x01, 0x02]);
    let frame = encode_frame(&Message::Shutdown).expect("frame");
    assert_eq!(frame, [0, 0, 0, 1, 0x3F]);
    let hello = encode(&Message::Hello {
        min: 1,
        max: 2,
        component: "net".to_owned(),
        version: "v".to_owned(),
    })
    .expect("encode");
    assert_eq!(
        hello,
        [
            0x01, 0, 1, 0, 2, 0, 0, 0, 3, b'n', b'e', b't', 0, 0, 0, 1, b'v'
        ]
    );
}

#[test]
fn every_truncation_fails_closed() {
    for message in all_messages() {
        let payload = encode(&message).expect("encode");
        for cut in 1..payload.len() {
            assert_eq!(
                decode(&payload[..cut]),
                Err(WireError::Truncated),
                "{message:?} cut at {cut}"
            );
        }
    }
}

#[test]
fn trailing_bytes_fail_closed() {
    for message in all_messages() {
        let mut payload = encode(&message).expect("encode");
        payload.push(0);
        assert_eq!(
            decode(&payload),
            Err(WireError::TrailingBytes { remaining: 1 })
        );
    }
}

#[test]
fn empty_and_unknown_tags_fail_closed() {
    assert_eq!(decode(&[]), Err(WireError::EmptyFrame));
    for tag in 0..=u8::MAX {
        let known = [
            TAG_HELLO,
            TAG_HELLO_ACK,
            TAG_HTTP_REQUEST,
            TAG_REQUEST_BODY,
            TAG_RESPONSE_HEAD,
            TAG_RESPONSE_BODY,
            TAG_ERROR,
            TAG_CANCEL,
            TAG_SHUTDOWN,
        ];
        if !known.contains(&tag) {
            assert_eq!(decode(&[tag]), Err(WireError::UnknownTag(tag)));
        }
    }
    for tag in TAG_RESERVED_WEBSOCKET_FIRST..=TAG_RESERVED_WEBSOCKET_LAST {
        assert_eq!(decode(&[tag]), Err(WireError::UnknownTag(tag)));
    }
}

#[test]
fn invalid_utf8_fails_closed() {
    let mut payload = vec![TAG_HELLO, 0, 1, 0, 1];
    payload.extend(str_field(&[0xFF, 0xFE]));
    payload.extend(str_field(b"v"));
    assert_eq!(
        decode(&payload),
        Err(WireError::InvalidUtf8 { field: "component" })
    );
}

#[test]
fn invalid_bool_and_codes_fail_closed() {
    let mut payload = encode(&Message::Cancel { id: 1 }).expect("encode");
    payload[0] = TAG_RESPONSE_BODY;
    payload.extend(str_field(b"x"));
    payload.push(2);
    assert_eq!(
        decode(&payload),
        Err(WireError::InvalidValue { field: "last" })
    );

    let mut error = encode(&Message::Error {
        id: 1,
        kind: ErrorKind::Denied,
        message: String::new(),
    })
    .expect("encode");
    error[9] = 0;
    assert_eq!(
        decode(&error),
        Err(WireError::InvalidValue { field: "kind" })
    );
    error[9] = 9;
    assert_eq!(
        decode(&error),
        Err(WireError::InvalidValue { field: "kind" })
    );
}

#[test]
fn zero_ids_are_rejected_except_connection_errors() {
    assert_eq!(
        encode(&Message::Cancel { id: 0 }),
        Err(WireError::InvalidValue { field: "id" })
    );
    assert_eq!(
        decode(&[TAG_CANCEL, 0, 0, 0, 0, 0, 0, 0, 0]),
        Err(WireError::InvalidValue { field: "id" })
    );
    assert!(
        encode(&Message::Error {
            id: CONNECTION_ID,
            kind: ErrorKind::Protocol,
            message: String::new(),
        })
        .is_ok()
    );
}

#[test]
fn method_codes_and_masks() {
    for method in Method::ALL {
        assert_eq!(Method::from_code(method.code()), Some(method));
    }
    assert_eq!(Method::from_code(7), None);
    assert_eq!(Method::mask_of(Method::ALL), Method::MASK_ALL);
    let mask = Method::mask_of([Method::Get, Method::Patch]);
    assert_eq!(
        Method::in_mask(mask).collect::<Vec<_>>(),
        vec![Method::Get, Method::Patch]
    );

    let bad_mask = Message::HttpRequest {
        id: 1,
        plugin_id: String::new(),
        grant: Grant {
            hosts: Vec::new(),
            methods: Some(0x80),
        },
        method: Method::Get,
        url: String::new(),
        headers: Vec::new(),
        timeout_ms: 0,
        max_body_bytes: 0,
        body_follows: false,
    };
    assert_eq!(
        encode(&bad_mask),
        Err(WireError::InvalidValue {
            field: "grant methods"
        })
    );
}

/// Builds the decode-side bytes of an `HttpRequest` with a raw grant blob.
fn raw_request_with_grant(grant: &[u8], method: u8) -> Vec<u8> {
    let mut payload = vec![TAG_HTTP_REQUEST];
    payload.extend(1u64.to_be_bytes());
    payload.extend(str_field(b"p"));
    payload.extend_from_slice(grant);
    payload.push(method);
    payload.extend(str_field(b"https://h/"));
    payload.extend(0u32.to_be_bytes());
    payload.extend(0u32.to_be_bytes());
    payload.extend(0u64.to_be_bytes());
    payload.push(0);
    payload
}

#[test]
fn grant_decoding_fails_closed() {
    // No hosts, has_methods=false with a non-zero mask byte.
    let grant = [0, 0, 0, 0, 0, 0x01];
    assert_eq!(
        decode(&raw_request_with_grant(&grant, 0)),
        Err(WireError::InvalidValue {
            field: "grant methods"
        })
    );
    // Unknown mask bit.
    let grant = [0, 0, 0, 0, 1, 0x80];
    assert_eq!(
        decode(&raw_request_with_grant(&grant, 0)),
        Err(WireError::InvalidValue {
            field: "grant methods"
        })
    );
    // Zero port.
    let mut grant = vec![0, 0, 0, 1];
    grant.extend(str_field(b"h"));
    grant.extend([0, 0, 0, 1, 0, 0, 0, 0]);
    assert_eq!(
        decode(&raw_request_with_grant(&grant, 0)),
        Err(WireError::InvalidValue {
            field: "grant port"
        })
    );
    // Empty host.
    let mut grant = vec![0, 0, 0, 1];
    grant.extend(str_field(b""));
    grant.extend([0, 0, 0, 0, 0, 0]);
    assert_eq!(
        decode(&raw_request_with_grant(&grant, 0)),
        Err(WireError::InvalidValue {
            field: "grant host"
        })
    );
    // Unknown method code.
    let grant = [0, 0, 0, 0, 0, 0];
    assert_eq!(
        decode(&raw_request_with_grant(&grant, 7)),
        Err(WireError::InvalidValue { field: "method" })
    );
    // Too many hosts: the count is rejected before any host is read.
    let grant = u32::try_from(MAX_GRANT_HOSTS + 1)
        .expect("fits")
        .to_be_bytes();
    assert_eq!(
        decode(&raw_request_with_grant(&grant, 0)),
        Err(WireError::LimitExceeded {
            field: "grant hosts",
            limit: MAX_GRANT_HOSTS
        })
    );
}

fn grant_with_hosts(count: usize, ports: usize) -> Grant {
    Grant {
        hosts: (0..count)
            .map(|i| GrantHost {
                host: format!("h{i}.example"),
                ports: (1..=u16::try_from(ports).expect("fits")).collect(),
            })
            .collect(),
        methods: None,
    }
}

fn request_with(grant: Grant, url: String, headers: Vec<(String, String)>) -> Message {
    Message::HttpRequest {
        id: 1,
        plugin_id: "p".to_owned(),
        grant,
        method: Method::Get,
        url,
        headers,
        timeout_ms: 0,
        max_body_bytes: 0,
        body_follows: false,
    }
}

#[test]
fn grant_limits_at_boundary_and_plus_one() {
    let at = request_with(
        grant_with_hosts(MAX_GRANT_HOSTS, MAX_GRANT_PORTS),
        String::new(),
        Vec::new(),
    );
    let payload = encode(&at).expect("at limit");
    assert_eq!(decode(&payload).expect("decode at limit"), at);
    assert_eq!(
        encode(&request_with(
            grant_with_hosts(MAX_GRANT_HOSTS + 1, 0),
            String::new(),
            Vec::new()
        )),
        Err(WireError::LimitExceeded {
            field: "grant hosts",
            limit: MAX_GRANT_HOSTS
        })
    );
    assert_eq!(
        encode(&request_with(
            grant_with_hosts(1, MAX_GRANT_PORTS + 1),
            String::new(),
            Vec::new()
        )),
        Err(WireError::LimitExceeded {
            field: "grant ports",
            limit: MAX_GRANT_PORTS
        })
    );
}

#[test]
fn url_limit_at_boundary_and_plus_one() {
    let at = request_with(Grant::default(), "u".repeat(MAX_URL_BYTES), Vec::new());
    assert_eq!(decode(&encode(&at).expect("at")).expect("decode"), at);
    let over = request_with(Grant::default(), "u".repeat(MAX_URL_BYTES + 1), Vec::new());
    assert_eq!(
        encode(&over),
        Err(WireError::LimitExceeded {
            field: "url",
            limit: MAX_URL_BYTES
        })
    );
    // Decode side: rewrite the url length of a valid payload to limit+1.
    let mut payload =
        encode(&request_with(Grant::default(), String::new(), Vec::new())).expect("encode");
    // tag(1) id(8) plugin_id(4+1) grant(4+1+1) method(1) => url len at 21.
    let url_len_at = 1 + 8 + 5 + 6 + 1;
    let over_len = u32::try_from(MAX_URL_BYTES + 1)
        .expect("fits")
        .to_be_bytes();
    payload[url_len_at..url_len_at + 4].copy_from_slice(&over_len);
    assert_eq!(
        decode(&payload),
        Err(WireError::LimitExceeded {
            field: "url",
            limit: MAX_URL_BYTES
        })
    );
}

#[test]
fn header_count_limit_at_boundary_and_plus_one() {
    let headers = |n: usize| -> Vec<(String, String)> {
        (0..n)
            .map(|i| (format!("x-h{i}"), "v".to_owned()))
            .collect()
    };
    let at = request_with(Grant::default(), String::new(), headers(MAX_HEADERS));
    assert_eq!(decode(&encode(&at).expect("at")).expect("decode"), at);
    assert_eq!(
        encode(&request_with(
            Grant::default(),
            String::new(),
            headers(MAX_HEADERS + 1)
        )),
        Err(WireError::LimitExceeded {
            field: "headers",
            limit: MAX_HEADERS
        })
    );
}

#[test]
fn header_bytes_limit_at_boundary_and_plus_one() {
    let name = "x".to_owned();
    let at = vec![(name.clone(), "v".repeat(MAX_HEADER_BYTES - name.len()))];
    let message = Message::ResponseHead {
        id: 1,
        status: 200,
        headers: at,
    };
    assert_eq!(
        decode(&encode(&message).expect("at")).expect("decode"),
        message
    );
    let over = vec![(name.clone(), "v".repeat(MAX_HEADER_BYTES - name.len() + 1))];
    assert_eq!(
        encode(&Message::ResponseHead {
            id: 1,
            status: 200,
            headers: over,
        }),
        Err(WireError::LimitExceeded {
            field: "header bytes",
            limit: MAX_HEADER_BYTES
        })
    );
}

#[test]
fn header_syntax_fails_closed() {
    for (name, value, field) in [
        ("", "v", "header name"),
        ("bad name", "v", "header name"),
        ("bad:name", "v", "header name"),
        ("ok", "a\r\nInjected: 1", "header value"),
        ("ok", "nul\0", "header value"),
    ] {
        let message = Message::ResponseHead {
            id: 1,
            status: 200,
            headers: vec![(name.to_owned(), value.to_owned())],
        };
        assert_eq!(
            encode(&message),
            Err(WireError::InvalidValue { field }),
            "{name:?}"
        );
    }
    // Decode side rejects the same injected value.
    let mut payload = vec![TAG_RESPONSE_HEAD];
    payload.extend(1u64.to_be_bytes());
    payload.extend(200u16.to_be_bytes());
    payload.extend(1u32.to_be_bytes());
    payload.extend(str_field(b"ok"));
    payload.extend(str_field(b"a\nb"));
    assert_eq!(
        decode(&payload),
        Err(WireError::InvalidValue {
            field: "header value"
        })
    );
}

#[test]
fn body_chunk_limit_at_boundary_and_plus_one() {
    let at = Message::ResponseBody {
        id: 1,
        data: vec![0xAB; MAX_BODY_CHUNK_BYTES],
        last: true,
    };
    let frame = encode_frame(&at).expect("at");
    assert!(frame.len() <= FRAME_HEADER_BYTES + MAX_FRAME_BYTES);
    assert_eq!(
        try_decode_frame(&frame).expect("decode").map(|(m, _)| m),
        Some(at)
    );
    assert_eq!(
        encode(&Message::RequestBody {
            id: 1,
            data: vec![0; MAX_BODY_CHUNK_BYTES + 1],
            last: false,
        }),
        Err(WireError::LimitExceeded {
            field: "data",
            limit: MAX_BODY_CHUNK_BYTES
        })
    );
    let mut payload = vec![TAG_RESPONSE_BODY];
    payload.extend(1u64.to_be_bytes());
    payload.extend(
        u32::try_from(MAX_BODY_CHUNK_BYTES + 1)
            .expect("fits")
            .to_be_bytes(),
    );
    assert_eq!(
        decode(&payload),
        Err(WireError::LimitExceeded {
            field: "data",
            limit: MAX_BODY_CHUNK_BYTES
        })
    );
}

#[test]
fn string_field_limits_at_boundary_and_plus_one() {
    let error = |n: usize| Message::Error {
        id: 1,
        kind: ErrorKind::Internal,
        message: "m".repeat(n),
    };
    let at = error(MAX_ERROR_MESSAGE_BYTES);
    assert_eq!(decode(&encode(&at).expect("at")).expect("decode"), at);
    assert_eq!(
        encode(&error(MAX_ERROR_MESSAGE_BYTES + 1)),
        Err(WireError::LimitExceeded {
            field: "message",
            limit: MAX_ERROR_MESSAGE_BYTES
        })
    );
    let hello = |n: usize| Message::Hello {
        min: 1,
        max: 1,
        component: "c".repeat(n),
        version: String::new(),
    };
    assert!(encode(&hello(MAX_COMPONENT_NAME_BYTES)).is_ok());
    assert_eq!(
        encode(&hello(MAX_COMPONENT_NAME_BYTES + 1)),
        Err(WireError::LimitExceeded {
            field: "component",
            limit: MAX_COMPONENT_NAME_BYTES
        })
    );
}

#[test]
fn frame_length_limit_at_boundary_and_plus_one() {
    // A length prefix of exactly MAX_FRAME_BYTES is accepted as a header
    // (incomplete until the payload arrives); +1 is rejected immediately.
    let at = u32::try_from(MAX_FRAME_BYTES).expect("fits").to_be_bytes();
    assert_eq!(try_decode_frame(&at), Ok(None));
    let over = u32::try_from(MAX_FRAME_BYTES + 1)
        .expect("fits")
        .to_be_bytes();
    assert_eq!(
        try_decode_frame(&over),
        Err(WireError::FrameTooLarge {
            len: MAX_FRAME_BYTES + 1
        })
    );
    let mut reader = FrameReader::new(&over[..]);
    assert_eq!(
        reader.read_frame(),
        Err(WireError::FrameTooLarge {
            len: MAX_FRAME_BYTES + 1
        })
    );
    assert_eq!(
        decode(&vec![TAG_SHUTDOWN; MAX_FRAME_BYTES + 1]),
        Err(WireError::FrameTooLarge {
            len: MAX_FRAME_BYTES + 1
        })
    );
    assert_eq!(
        FrameReader::new(&[0u8, 0, 0, 0][..]).read_frame(),
        Err(WireError::EmptyFrame)
    );
}

#[test]
fn frame_reader_streams_and_detects_truncation() {
    let mut stream = Vec::new();
    for message in all_messages() {
        write_frame(&mut stream, &message).expect("write");
    }
    let mut reader = FrameReader::new(stream.as_slice());
    for message in all_messages() {
        assert_eq!(reader.read_message().expect("read"), Some(message));
    }
    assert_eq!(reader.read_message().expect("eof"), None);

    let frame = encode_frame(&Message::Cancel { id: 5 }).expect("frame");
    for cut in 1..frame.len() {
        assert_eq!(
            FrameReader::new(&frame[..cut]).read_message(),
            Err(WireError::Truncated),
            "cut at {cut}"
        );
    }
}

/// A reader yielding one byte per call exercises the incremental header path.
struct OneByte<'a>(&'a [u8]);

impl Read for OneByte<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match (self.0.split_first(), buf.first_mut()) {
            (Some((byte, rest)), Some(slot)) => {
                *slot = *byte;
                self.0 = rest;
                Ok(1)
            }
            _ => Ok(0),
        }
    }
}

#[test]
fn frame_reader_handles_short_reads() {
    let frame = encode_frame(&sample_request()).expect("frame");
    let mut reader = FrameReader::new(OneByte(&frame));
    assert_eq!(reader.read_message().expect("read"), Some(sample_request()));
    assert_eq!(reader.read_message().expect("eof"), None);
}

#[test]
fn try_decode_frame_waits_for_complete_input() {
    let frame = encode_frame(&Message::Shutdown).expect("frame");
    for cut in 0..frame.len() {
        assert_eq!(try_decode_frame(&frame[..cut]), Ok(None));
    }
    let mut two = frame.clone();
    two.extend(encode_frame(&Message::Cancel { id: 1 }).expect("frame"));
    let (first, used) = try_decode_frame(&two).expect("decode").expect("full");
    assert_eq!(first, Message::Shutdown);
    let (second, _) = try_decode_frame(&two[used..])
        .expect("decode")
        .expect("full");
    assert_eq!(second, Message::Cancel { id: 1 });
}

#[test]
fn debug_redacts_urls_headers_and_bodies() {
    let rendered = format!(
        "{:?} {:?}",
        sample_request(),
        Message::ResponseBody {
            id: 1,
            data: b"secret-body".to_vec(),
            last: true
        }
    );
    assert!(!rendered.contains("api.example.com/v1"));
    assert!(!rendered.contains("application/json"));
    assert!(!rendered.contains("secret-body"));
}

#[test]
fn error_kind_names_are_stable() {
    let names: Vec<_> = ErrorKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(
        names,
        [
            "denied",
            "offline",
            "timeout",
            "budget",
            "tls",
            "protocol",
            "component_lost",
            "internal"
        ]
    );
    for kind in ErrorKind::ALL {
        assert_eq!(ErrorKind::from_code(kind.code()), Some(kind));
    }
    assert_eq!(ErrorKind::from_code(0), None);
}
