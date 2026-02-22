use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicU64, Ordering},
};
use std::time::Instant;

use crate::models::ProgressUpdate;

pub type ProgressCallback = Arc<dyn Fn(ProgressUpdate) + Send + Sync + 'static>;

#[derive(Clone)]
pub struct ProgressTracker {
    phase: String,
    total: u64,
    start: Instant,
    processed: Arc<AtomicU64>,
    last_percent: Arc<AtomicU8>,
    callback: Option<ProgressCallback>,
}

impl ProgressTracker {
    pub fn new(phase: impl Into<String>, total: u64, callback: Option<ProgressCallback>) -> Self {
        Self {
            phase: phase.into(),
            total: total.max(1),
            start: Instant::now(),
            processed: Arc::new(AtomicU64::new(0)),
            last_percent: Arc::new(AtomicU8::new(0)),
            callback,
        }
    }

    pub fn add(&self, bytes: u64, message: impl Into<String>) {
        let processed = self.processed.fetch_add(bytes, Ordering::Relaxed) + bytes;
        let percent = ((processed as u128 * 100) / self.total as u128).min(100) as u8;

        loop {
            let previous = self.last_percent.load(Ordering::Relaxed);
            if percent <= previous {
                return;
            }

            match self.last_percent.compare_exchange(
                previous,
                percent,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.emit(percent, processed, message.into());
                    return;
                }
                Err(current) if percent <= current => return,
                Err(_) => continue,
            }
        }
    }

    pub fn finish(&self, message: impl Into<String>) {
        self.last_percent.store(100, Ordering::Relaxed);
        self.emit(100, self.total, message.into());
    }

    fn emit(&self, percent: u8, processed: u64, message: String) {
        if let Some(cb) = &self.callback {
            let elapsed = self.start.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                processed as f64 / elapsed
            } else {
                0.0
            };
            let remaining = self.total.saturating_sub(processed) as f64;
            let eta = if rate > 0.0 {
                Some((remaining / rate).round() as u64)
            } else {
                None
            };

            cb(ProgressUpdate {
                phase: self.phase.clone(),
                percent,
                processed_bytes: processed.min(self.total),
                total_bytes: self.total,
                eta_seconds: eta,
                message,
            });
        }
    }
}
