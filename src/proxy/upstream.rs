use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

use crate::error::AppError;

pub struct UnixSocketProxy {
    socket_path: String,
}

impl UnixSocketProxy {
    pub fn new(socket_path: String) -> Self {
        Self { socket_path }
    }

    pub async fn forward(
        &self,
        req: Request<BoxBody<Bytes, hyper::Error>>,
    ) -> Result<hyper::Response<Incoming>, AppError> {
        let stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            AppError::Proxy(format!(
                "Failed to connect to {}: {}",
                self.socket_path, e
            ))
        })?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io)
            .await
            .map_err(|e| AppError::Proxy(format!("Handshake failed: {}", e)))?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::error!("Connection error: {}", e);
            }
        });
        sender
            .send_request(req)
            .await
            .map_err(|e| AppError::Proxy(format!("Request failed: {}", e)))
    }
}
