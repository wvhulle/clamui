use std::{
    fs::File,
    io::{self, Read},
    os::fd::OwnedFd,
};

use rustix::pipe::{PipeFlags, pipe_with};

pub fn pipe_content_for_child(
    mut content_source: impl Read + Send + 'static,
) -> io::Result<OwnedFd> {
    let (pipe_reader, pipe_writer) = pipe_with(PipeFlags::CLOEXEC)?;
    std::thread::spawn(move || {
        let _reader_closed = io::copy(&mut content_source, &mut File::from(pipe_writer));
    });
    Ok(pipe_reader)
}

#[cfg(test)]
mod content_pipe_tests {
    use super::*;

    #[test]
    fn the_child_end_reads_the_whole_content() {
        let mut received_content = Vec::new();
        File::from(pipe_content_for_child(io::Cursor::new(b"piped bytes".to_vec())).unwrap())
            .read_to_end(&mut received_content)
            .unwrap();
        assert_eq!(received_content, b"piped bytes");
    }
}
