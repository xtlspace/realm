use std::io::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[inline]
pub async fn run_relay(mut local: TcpStream, mut remote: TcpStream, prefix: Option<Vec<u8>>) -> Result<()> {
    // replay the bytes consumed by sni sniffing
    if let Some(prefix) = prefix {
        remote.write_all(&prefix).await?;
    }

    #[cfg(target_os = "linux")]
    {
        use std::io::ErrorKind;
        match realm_io::bidi_zero_copy(&mut local, &mut remote).await {
            Ok(_) => Ok(()),
            Err(ref e) if e.kind() == ErrorKind::InvalidInput => {
                realm_io::bidi_copy(&mut local, &mut remote).await.map(|_| ())
            }
            Err(e) => Err(e),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        realm_io::bidi_copy(&mut local, &mut remote).await.map(|_| ())
    }
}
