use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::collections::HashMap;

use tokio::net::UdpSocket;

pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|x| x.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone)]
struct Assoc {
    socket: Arc<UdpSocket>,
    raddr: SocketAddr,
    activity: Arc<AtomicU64>,
    replied: Arc<AtomicBool>,
}

pub struct SockMap(RwLock<HashMap<SocketAddr, Assoc>>);

impl SockMap {
    pub fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    #[inline]
    pub fn find(&self, addr: &SocketAddr) -> Option<(Arc<UdpSocket>, SocketAddr, Arc<AtomicBool>)> {
        // fetch the lock

        let sockmap = self.0.read().unwrap();

        sockmap
            .get(addr)
            .map(|x| (x.socket.clone(), x.raddr, x.replied.clone()))

        // drop the lock
    }

    #[inline]
    pub fn insert(
        &self,
        addr: SocketAddr,
        socket: Arc<UdpSocket>,
        raddr: SocketAddr,
    ) -> (Arc<AtomicU64>, Arc<AtomicBool>) {
        // fetch the lock
        let mut sockmap = self.0.write().unwrap();

        let activity = Arc::new(AtomicU64::new(now_millis()));
        let replied = Arc::new(AtomicBool::new(false));

        let _ = sockmap.insert(
            addr,
            Assoc {
                socket,
                raddr,
                activity: activity.clone(),
                replied: replied.clone(),
            },
        );

        // drop the lock
        (activity, replied)
    }

    #[inline]
    pub fn find_or_insert<E, F>(
        &self,
        addr: &SocketAddr,
        f: F,
    ) -> Result<(Arc<UdpSocket>, SocketAddr, Arc<AtomicBool>), E>
    where
        F: FnOnce() -> Result<(Arc<UdpSocket>, SocketAddr), E>,
    {
        match self.find(addr) {
            Some(x) => Ok(x),
            None => {
                let (socket, raddr) = f()?;
                let (_, replied) = self.insert(*addr, socket.clone(), raddr);
                Ok((socket, raddr, replied))
            }
        }
    }

    /// Mark client activity of an association.
    #[inline]
    pub fn touch(&self, addr: &SocketAddr) {
        let sockmap = self.0.read().unwrap();

        if let Some(x) = sockmap.get(addr) {
            x.activity.store(now_millis(), Ordering::Relaxed);
        }
    }

    /// Mark that the remote side has replied at least once.
    #[inline]
    pub fn mark_replied(&self, addr: &SocketAddr) {
        let sockmap = self.0.read().unwrap();

        if let Some(x) = sockmap.get(addr) {
            x.replied.store(true, Ordering::Relaxed);
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
