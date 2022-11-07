use std::cell::RefCell;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

pub struct ReaderBuf {
    pub buf: Vec<u8>,
    pub last: RefCell<Vec<u8>>,
}

impl Default for ReaderBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl ReaderBuf {
    pub fn new() -> Self {
        Self {
            buf: vec![0; 4096],
            last: Default::default(),
        }
    }

    pub fn fill_from_last(&mut self) -> usize {
        let len = self.last.borrow().len();
        if len > 0 {
            let l = &mut self.last.borrow_mut();
            self.buf[..l.len()].copy_from_slice(l.as_slice());
            let off = l.len();
            l.clear();
            off
        } else {
            0
        }
    }

    pub fn push_to_last(&self, i: &[u8]) {
        let l = &mut self.last.borrow_mut();
        let len = i.len();
        l.resize(len, 0);
        l[..len].copy_from_slice(i);
    }

    pub async fn read_from(
        &mut self,
        source: &mut TlsStream<TcpStream>,
    ) -> Result<usize, std::io::Error> {
        let off = self.fill_from_last();

        let bytes = source.read(&mut self.buf.as_mut_slice()[off..]).await?;

        if bytes == 0 {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Read of length 0 from server",
            ))
        } else {
            Ok(off + bytes)
        }
    }
}
