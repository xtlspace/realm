use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;

use tokio::net::UdpSocket;

#[derive(Clone)]
struct Assoc {
    socket: Arc<UdpSocket>,
    raddr: SocketAddr,
}

pub struct SockMap(RwLock<HashMap<SocketAddr, Assoc>>);

impl SockMap {
    pub fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    #[inline]
    pub fn find(&self, addr: &SocketAddr) -> Option<(Arc<UdpSocket>, SocketAddr)> {
        // fetch the lock

        let sockmap = self.0.read().unwrap();

        sockmap.get(addr).map(|x| (x.socket.clone(), x.raddr))

        // drop the lock
    }

    #[inline]
    pub fn insert(&self, addr: SocketAddr, socket: Arc<UdpSocket>, raddr: SocketAddr) {
        // fetch the lock
        let mut sockmap = self.0.write().unwrap();

        let _ = sockmap.insert(addr, Assoc { socket, raddr });

        // drop the lock
    }

    #[inline]
    pub fn find_or_insert<E, F>(&self, addr: &SocketAddr, f: F) -> Result<(Arc<UdpSocket>, SocketAddr), E>
    where
        F: FnOnce() -> Result<(Arc<UdpSocket>, SocketAddr), E>,
    {
        match self.find(addr) {
            Some(x) => Ok(x),
            None => {
                let (socket, raddr) = f()?;
                self.insert(*addr, socket.clone(), raddr);
                Ok((socket, raddr))
            }
        }
    }

    #[inline]
    pub fn remove(&self, addr: &SocketAddr) {
        // fetch the lock
        let mut sockmap = self.0.write().unwrap();

        let _ = sockmap.remove(addr);

        // drop the lock
    }
}
