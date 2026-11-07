use std::{
    io::{Read, Write},
    net::TcpListener,
    thread::JoinHandle,
};

const HEADER_END: &[u8] = b"\r\n\r\n";
const CHUNKED_BODY_END: &[u8] = b"0\r\n\r\n";

pub struct RecordedAnswerStub {
    pub endpoint_url: String,
    request_capture: JoinHandle<Vec<u8>>,
}

fn header_end_position(received_bytes: &[u8]) -> Option<usize> {
    received_bytes
        .windows(HEADER_END.len())
        .position(|byte_window| byte_window == HEADER_END)
        .map(|header_position| header_position + HEADER_END.len())
}

fn declared_body_length(header_text: &str) -> Option<usize> {
    header_text.lines().find_map(|header_line| {
        let (header_name, header_value) = header_line.split_once(':')?;
        header_name
            .trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| header_value.trim().parse().ok())
            .flatten()
    })
}

fn request_is_complete(received_bytes: &[u8]) -> bool {
    let Some(body_start) = header_end_position(received_bytes) else {
        return false;
    };
    let header_text = String::from_utf8_lossy(&received_bytes[..body_start]);
    match declared_body_length(&header_text) {
        Some(body_length) => received_bytes.len() >= body_start + body_length,
        None if header_text
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked") =>
        {
            received_bytes.ends_with(CHUNKED_BODY_END)
        }
        None => true,
    }
}

pub fn serve_recorded_answer(
    status_line: &'static str,
    answer_body: &'static [u8],
) -> RecordedAnswerStub {
    let stub_listener = TcpListener::bind("127.0.0.1:0").expect("stub listener");
    let endpoint_url = format!(
        "http://{}/",
        stub_listener.local_addr().expect("stub address")
    );
    let request_capture = std::thread::spawn(move || {
        let (mut client_stream, _client_address) = stub_listener.accept().expect("stub client");
        let mut received_bytes = Vec::new();
        let mut read_buffer = [0_u8; 8192];
        while !request_is_complete(&received_bytes) {
            let read_count = client_stream.read(&mut read_buffer).expect("stub read");
            if read_count == 0 {
                break;
            }
            received_bytes.extend_from_slice(&read_buffer[..read_count]);
        }
        let answer_head = format!(
            "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: \
             {}\r\nConnection: close\r\n\r\n",
            answer_body.len()
        );
        client_stream
            .write_all(answer_head.as_bytes())
            .and_then(|()| client_stream.write_all(answer_body))
            .expect("stub answer");
        received_bytes
    });
    RecordedAnswerStub {
        endpoint_url,
        request_capture,
    }
}

impl RecordedAnswerStub {
    pub fn captured_request(self) -> String {
        String::from_utf8_lossy(&self.request_capture.join().expect("stub thread")).into_owned()
    }
}
