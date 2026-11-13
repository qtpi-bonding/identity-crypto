use crate::Clock;
use bytes::Bytes;
use http::HeaderMap;
use http_body::{Body as HttpBody, Frame};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::{sleep, Sleep};
use tonic::body::Body;
use tonic::Status;

/// A server-streaming response that ends, with an `UNAUTHENTICATED` status in
/// its trailers, once the caller's session certificate has expired.
///
/// The check runs whenever the stream is polled, and a timer fires it for a
/// stream that is idle at the deadline, so a quiet stream cannot outlive the
/// session. The clock is the layer's own, so a test moves it by hand.
pub(super) struct ExpiringBody {
    inner: Body,
    clock: Arc<dyn Clock>,
    not_after: i64,
    timer: Pin<Box<Sleep>>,
    done: bool,
}

impl ExpiringBody {
    pub(super) fn new(inner: Body, clock: Arc<dyn Clock>, not_after: i64) -> Self {
        let timer = Box::pin(sleep(until(&*clock, not_after)));
        Self {
            inner,
            clock,
            not_after,
            timer,
            done: false,
        }
    }

    fn end(&mut self) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        self.done = true;
        let mut trailers = HeaderMap::new();
        Status::unauthenticated("the session certificate has expired")
            .add_header(&mut trailers)
            .ok();
        Poll::Ready(Some(Ok(Frame::trailers(trailers))))
    }
}

/// The wait until `not_after`, at least a second, so a timer that fires a
/// little early re-arms instead of spinning.
fn until(clock: &dyn Clock, not_after: i64) -> Duration {
    Duration::from_secs((not_after - clock.now_unix()).max(1) as u64)
}

impl HttpBody for ExpiringBody {
    type Data = Bytes;
    type Error = Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        let this = &mut *self;
        if this.done {
            return Poll::Ready(None);
        }
        if this.clock.now_unix() >= this.not_after {
            return this.end();
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(None) => {
                this.done = true;
                return Poll::Ready(None);
            }
            Poll::Ready(frame) => return Poll::Ready(frame),
            Poll::Pending => {}
        }
        // The stream is idle: wait for the deadline.
        while this.timer.as_mut().poll(cx).is_ready() {
            if this.clock.now_unix() >= this.not_after {
                return this.end();
            }
            let next = until(&*this.clock, this.not_after);
            this.timer
                .as_mut()
                .reset(tokio::time::Instant::now() + next);
        }
        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }
}
