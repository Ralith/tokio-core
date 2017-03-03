use std::io;
use std::net::{SocketAddr, Ipv4Addr, SocketAddrV4};

use futures::{Async, Poll, Stream, Sink, StartSend, AsyncSink};

use net::UdpSocket;

/// Encoding of frames via buffers.
///
/// This trait is used when constructing an instance of `UdpFramed` and provides
/// the `In` and `Out` types which are decoded and encoded from the socket,
/// respectively.
///
/// Because UDP is a connectionless protocol, the `decode` method receives the
/// address where data came from and the `encode` method is also responsible for
/// determining the remote host to which the datagram should be sent
///
/// The trait itself is implemented on a type that can track state for decoding
/// or encoding, which is particularly useful for streaming parsers. In many
/// cases, though, this type will simply be a unit struct (e.g. `struct
/// HttpCodec`).
pub trait UdpCodec {
    /// The type of decoded frames.
    type In;

    /// The type of frames to be encoded.
    type Out;

    /// The type of fatal decoding errors.
    type Error;

    /// Attempts to decode a frame from the provided buffer of bytes.
    ///
    /// This method is called by `UdpFramed` on a single datagram which has been
    /// read from a socket. The `buf` argument contains the data that was
    /// received from the remote address, and `src` is the address the data came
    /// from. Note that typically this method should require the entire contents
    /// of `buf` to be valid or otherwise return an error with trailing data.
    ///
    /// Finally, if the bytes in the buffer are malformed then an error is
    /// returned indicating why. This informs `Framed` that the stream is now
    /// corrupt and should be terminated.
    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> Result<Self::In, Self::Error>;

    /// Encodes a frame into the buffer provided.
    ///
    /// This method will encode `msg` into the byte buffer provided by `buf`.
    /// The `buf` provided is an internal buffer of the `Framed` instance and
    /// will be written out when possible.
    ///
    /// The encode method also determines the destination to which the buffer
    /// should be directed, which will be returned as a `SocketAddr`.
    fn encode(&mut self, msg: Self::Out, buf: &mut Vec<u8>) -> SocketAddr;
}

/// A unified `Stream` and `Sink` interface to an underlying `UdpSocket`, using
/// the `UdpCodec` trait to encode and decode frames.
///
/// You can acquire a `UdpFramed` instance by using the `UdpSocket::framed`
/// adapter.
pub struct UdpFramed<C> {
    socket: UdpSocket,
    codec: C,
    rd: Vec<u8>,
    wr: Vec<u8>,
    out_addr: SocketAddr,
}

impl<C: UdpCodec> Stream for UdpFramed<C>
    where C::Error: From<io::Error>
{
    type Item = io::Result<C::In>;
    type Error = C::Error;

    fn poll(&mut self) -> Poll<Option<io::Result<C::In>>, C::Error> {
        match self.socket.recv_from(&mut self.rd) {
            Ok((n, addr)) => {
                trace!("received {} bytes, decoding", n);
                let frame = try!(self.codec.decode(&addr, &self.rd[..n]));
                trace!("frame decoded from buffer");
                Ok(Async::Ready(Some(Ok(frame))))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Async::NotReady),
            Err(e) => {
                // UDP reads can produce ECONNRESET if an ICMP error is
                // received, but (unlike for TCP) this says nothing about
                // whether future reads will succeed.
                if e.kind() == io::ErrorKind::ConnectionReset {
                    Ok(Async::Ready(Some(Err(e))))
                } else {
                    Err(e.into())
                }
            },
        }
    }
}

impl<C: UdpCodec> Sink for UdpFramed<C> {
    type SinkItem = C::Out;
    type SinkError = io::Error;

    fn start_send(&mut self, item: C::Out) -> StartSend<C::Out, io::Error> {
        if self.wr.len() > 0 {
            try!(self.poll_complete());
            if self.wr.len() > 0 {
                return Ok(AsyncSink::NotReady(item));
            }
        }

        self.out_addr = self.codec.encode(item, &mut self.wr);
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        trace!("flushing framed transport");

        if self.wr.is_empty() {
            return Ok(Async::Ready(()))
        }

        trace!("writing; remaining={}", self.wr.len());
        let n = match self.socket.send_to(&self.wr, &self.out_addr) {
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Async::NotReady),

            // Linux can return EPERM if the firewall packet queue is full. We
            // drop the message because we have no way of being informed when
            // the queue is no longer full, but do not return an error from the
            // sink because future writes are likely to succeed.
            Err(ref e) if e.kind() == io::ErrorKind::PermissionDenied => {
                trace!("dropped datagram due to EPERM");
                self.wr.clear();
                return Ok(Async::Ready(()))
            },

            Err(e) => return Err(e),
        };
        trace!("written {}", n);
        let wrote_all = n == self.wr.len();
        self.wr.clear();
        if wrote_all {
            Ok(Async::Ready(()))
        } else {
            Err(io::Error::new(io::ErrorKind::Other,
                               "failed to write entire datagram to socket"))
        }
    }
}

pub fn new<C: UdpCodec>(socket: UdpSocket, codec: C) -> UdpFramed<C> {
    UdpFramed {
        socket: socket,
        codec: codec,
        out_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
        rd: vec![0; 64 * 1024],
        wr: Vec::with_capacity(8 * 1024),
    }
}

impl<C> UdpFramed<C> {
    /// Returns a reference to the underlying I/O stream wrapped by `Framed`.
    ///
    /// Note that care should be taken to not tamper with the underlying stream
    /// of data coming in as it may corrupt the stream of frames otherwise being
    /// worked with.
    pub fn get_ref(&self) -> &UdpSocket {
        &self.socket
    }

    /// Returns a mutable reference to the underlying I/O stream wrapped by
    /// `Framed`.
    ///
    /// Note that care should be taken to not tamper with the underlying stream
    /// of data coming in as it may corrupt the stream of frames otherwise being
    /// worked with.
    pub fn get_mut(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }

    /// Consumes the `Framed`, returning its underlying I/O stream.
    ///
    /// Note that care should be taken to not tamper with the underlying stream
    /// of data coming in as it may corrupt the stream of frames otherwise being
    /// worked with.
    pub fn into_inner(self) -> UdpSocket {
        self.socket
    }
}
