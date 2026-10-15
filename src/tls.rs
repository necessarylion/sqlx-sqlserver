use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::protocol::packet::{
    encode_message, PacketFrameError, PacketHeader, PacketHeaderError, PacketType,
    PACKET_HEADER_LEN,
};

pub(crate) struct TlsPreloginStream<S> {
    stream: S,
    handshake: bool,
    header_buf: [u8; PACKET_HEADER_LEN],
    header_pos: usize,
    read_remaining: usize,
    write_buf: Vec<u8>,
    send_buf: Vec<u8>,
}

impl<S> TlsPreloginStream<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            handshake: false,
            header_buf: [0; PACKET_HEADER_LEN],
            header_pos: 0,
            read_remaining: 0,
            write_buf: Vec::new(),
            send_buf: Vec::new(),
        }
    }

    pub(crate) fn start_handshake(&mut self) {
        self.handshake = true;
    }

    pub(crate) fn finish_handshake(&mut self) {
        self.handshake = false;
    }
}

impl<S: AsyncWrite + Unpin> TlsPreloginStream<S> {
    /// Sends the buffered TLS handshake bytes as one PRELOGIN message.
    ///
    /// SQL Server closes the connection when one TLS flight is split over
    /// several PRELOGIN messages. Some TLS backends (Secure Transport on macOS)
    /// flush after every TLS record, so we do not send on flush. We send when
    /// the TLS engine wants to read the answer, which is the end of a flight.
    fn poll_send_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.send_buf.is_empty() && !self.write_buf.is_empty() {
            self.send_buf =
                wrap_prelogin_tls_payload(&self.write_buf, 4096).map_err(packet_frame_error)?;
            self.write_buf.clear();
        }

        while !self.send_buf.is_empty() {
            let written = ready!(Pin::new(&mut self.stream).poll_write(cx, &self.send_buf))?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write TLS handshake packet",
                )));
            }
            self.send_buf.drain(..written);
        }

        Pin::new(&mut self.stream).poll_flush(cx)
    }
}

impl<S> std::fmt::Debug for TlsPreloginStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsPreloginStream")
            .field("handshake", &self.handshake)
            .field("read_remaining", &self.read_remaining)
            .field("write_buf_len", &self.write_buf.len())
            .finish_non_exhaustive()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsPreloginStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.handshake {
            return Pin::new(&mut self.stream).poll_read(cx, buf);
        }

        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        ready!(self.poll_send_handshake(cx))?;

        if self.read_remaining == 0 {
            while self.header_pos < PACKET_HEADER_LEN {
                let mut scratch = [0; PACKET_HEADER_LEN];
                let remaining = PACKET_HEADER_LEN - self.header_pos;
                let mut header_read = ReadBuf::new(&mut scratch[..remaining]);
                ready!(Pin::new(&mut self.stream).poll_read(cx, &mut header_read))?;

                let read = header_read.filled().len();
                if read == 0 {
                    let message = if self.header_pos == 0 {
                        "SQL Server closed the connection before sending a TDS PRELOGIN packet during TLS handshake"
                    } else {
                        "SQL Server closed the connection in the middle of a TDS PRELOGIN packet header during TLS handshake"
                    };
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, message)));
                }

                let header_pos = self.header_pos;
                self.header_buf[header_pos..header_pos + read]
                    .copy_from_slice(header_read.filled());
                self.header_pos += read;
            }

            let header = PacketHeader::decode(&self.header_buf).map_err(packet_header_io_error)?;
            if header.packet_type != PacketType::PRE_LOGIN {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "expected TLS handshake bytes in PRELOGIN packet, got packet type 0x{:02x}",
                        header.packet_type.code()
                    ),
                )));
            }

            self.read_remaining = usize::from(header.length)
                .checked_sub(PACKET_HEADER_LEN)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid TDS packet length")
                })?;
            self.header_pos = 0;
        }

        let max_read = std::cmp::min(self.read_remaining, buf.remaining());
        let mut limited_buf = buf.take(max_read);
        ready!(Pin::new(&mut self.stream).poll_read(cx, &mut limited_buf))?;

        let read = limited_buf.filled().len();
        if read == 0 && self.read_remaining > 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "SQL Server closed the connection in the middle of a TDS PRELOGIN TLS payload",
            )));
        }

        buf.advance(read);
        self.read_remaining -= read;

        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsPreloginStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.handshake {
            // The last handshake flight can still be buffered here.
            ready!(self.poll_send_handshake(cx))?;
            return Pin::new(&mut self.stream).poll_write(cx, buf);
        }

        self.write_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.handshake {
            return Pin::new(&mut self.stream).poll_flush(cx);
        }

        self.poll_send_handshake(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn wrap_prelogin_tls_payload(
    payload: &[u8],
    packet_size: usize,
) -> Result<Vec<u8>, PacketFrameError> {
    encode_message(PacketType::PRE_LOGIN, payload, packet_size)
}

fn packet_header_io_error(error: PacketHeaderError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn packet_frame_error(error: PacketFrameError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("failed to wrap TLS handshake bytes in a TDS PRELOGIN packet: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_tls_handshake_bytes_as_prelogin_packets() {
        let packet = wrap_prelogin_tls_payload(b"hello", 512).unwrap();
        let header = PacketHeader::decode(&packet[..PACKET_HEADER_LEN]).unwrap();

        assert_eq!(PacketType::PRE_LOGIN, header.packet_type);
        assert_eq!(PACKET_HEADER_LEN + 5, usize::from(header.length));
        assert_eq!(b"hello", &packet[PACKET_HEADER_LEN..]);
    }

    #[tokio::test]
    async fn sends_one_tls_flight_as_one_prelogin_packet() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, mut server) = tokio::io::duplex(4096);
        let mut stream = TlsPreloginStream::new(client);
        stream.start_handshake();

        // Secure Transport writes and flushes each TLS record on its own.
        stream.write_all(b"first").await.unwrap();
        stream.flush().await.unwrap();
        stream.write_all(b"second").await.unwrap();
        stream.flush().await.unwrap();

        // The TLS engine now waits for the server answer.
        let reply = encode_message(PacketType::PRE_LOGIN, b"ok", 512).unwrap();
        server.write_all(&reply).await.unwrap();
        let mut answer = [0; 2];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(b"ok", &answer);

        let mut packet = vec![0; PACKET_HEADER_LEN + 11];
        server.read_exact(&mut packet).await.unwrap();
        let header = PacketHeader::decode(&packet[..PACKET_HEADER_LEN]).unwrap();
        assert_eq!(PacketType::PRE_LOGIN, header.packet_type);
        assert_eq!(packet.len(), usize::from(header.length));
        assert_eq!(b"firstsecond", &packet[PACKET_HEADER_LEN..]);
    }
}
