//! In-memory ring buffer of log lines for the UI, fed by a `tracing` layer.

use std::collections::VecDeque;
use std::fmt::{self, Write as _};
use std::sync::Arc;

use chrono::{DateTime, Local};
use parking_lot::Mutex;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub time: DateTime<Local>,
    pub level: Level,
    pub target: String,
    pub message: String,
}

/// Shared ring buffer of recent log lines.
#[derive(Debug)]
pub struct LogBuffer {
    lines: Mutex<VecDeque<LogLine>>,
    capacity: usize,
    /// Incremented on every push, lets the UI detect changes cheaply.
    generation: Mutex<u64>,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            lines: Mutex::new(VecDeque::with_capacity(capacity.min(4096))),
            capacity: capacity.max(1),
            generation: Mutex::new(0),
        })
    }

    pub fn push(&self, line: LogLine) {
        let mut lines = self.lines.lock();
        if lines.len() == self.capacity {
            lines.pop_front();
        }
        lines.push_back(line);
        *self.generation.lock() += 1;
    }

    /// Oldest first.
    pub fn lines(&self) -> Vec<LogLine> {
        self.lines.lock().iter().cloned().collect()
    }

    pub fn generation(&self) -> u64 {
        *self.generation.lock()
    }

    pub fn clear(&self) {
        self.lines.lock().clear();
        *self.generation.lock() += 1;
    }

    /// A `tracing` layer writing into this buffer.
    pub fn layer(self: &Arc<Self>) -> LogBufferLayer {
        LogBufferLayer {
            buffer: self.clone(),
        }
    }
}

pub struct LogBufferLayer {
    buffer: Arc<LogBuffer>,
}

impl<S: Subscriber> Layer<S> for LogBufferLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let meta = event.metadata();
        self.buffer.push(LogLine {
            time: Local::now(),
            level: *meta.level(),
            target: meta.target().to_string(),
            message: visitor.finish(),
        });
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

impl MessageVisitor {
    fn finish(self) -> String {
        match (self.message.is_empty(), self.fields.is_empty()) {
            (_, true) => self.message,
            (true, false) => self.fields,
            (false, false) => format!("{} {}", self.message, self.fields),
        }
    }

    fn add_field(&mut self, name: &str, value: fmt::Arguments<'_>) {
        if !self.fields.is_empty() {
            self.fields.push(' ');
        }
        let _ = write!(self.fields, "{name}={value}");
    }
}

impl Visit for MessageVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.add_field(field.name(), format_args!("{value}"));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.add_field(field.name(), format_args!("{value:?}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    #[test]
    fn captures_events_with_fields() {
        let buffer = LogBuffer::new(2);
        let subscriber = tracing_subscriber::registry().with(buffer.layer());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("first");
            tracing::warn!(port = 80, name = "x", "second");
            tracing::error!(code = 5);
        });
        let lines = buffer.lines();
        assert_eq!(lines.len(), 2, "capacity is respected");
        assert_eq!(lines[0].level, Level::WARN);
        assert_eq!(lines[0].message, "second port=80 name=x");
        assert_eq!(lines[1].message, "code=5");
        assert_eq!(lines[1].level, Level::ERROR);
        assert!(lines[1].target.contains("logbuf"));
        assert_eq!(buffer.generation(), 3);

        buffer.clear();
        assert!(buffer.lines().is_empty());
        assert_eq!(buffer.generation(), 4);
    }

    #[test]
    fn zero_capacity_is_clamped() {
        let buffer = LogBuffer::new(0);
        for i in 0..3 {
            buffer.push(LogLine {
                time: Local::now(),
                level: Level::INFO,
                target: "t".into(),
                message: i.to_string(),
            });
        }
        assert_eq!(buffer.lines().len(), 1);
        assert_eq!(buffer.lines()[0].message, "2");
    }
}
