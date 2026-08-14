//! Serialized command execution and event delivery.

use super::{Command, Event, ProfileSession, handle_command};
use anyhow::Result;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;

const COMMAND_QUEUE_SIZE: usize = 16;

pub struct UiService {
    commands: SyncSender<Command>,
    events: Arc<Mutex<Receiver<Event>>>,
}

impl UiService {
    pub fn new() -> Self {
        let (commands, command_rx) = mpsc::sync_channel(COMMAND_QUEUE_SIZE);
        let (event_tx, event_rx) = mpsc::channel();
        thread::spawn(move || worker_loop(command_rx, event_tx));
        Self {
            commands,
            events: Arc::new(Mutex::new(event_rx)),
        }
    }

    pub fn submit(&self, command: Command) -> Result<()> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                TrySendError::Full(_) => anyhow::anyhow!("client operation queue is busy"),
                TrySendError::Disconnected(_) => anyhow::anyhow!("client worker stopped"),
            })
    }

    pub fn try_submit(&self, command: Command) -> bool {
        self.commands.try_send(command).is_ok()
    }

    pub fn drain_events(&self) -> Vec<Event> {
        let Ok(events) = self.events.lock() else {
            return Vec::new();
        };
        events.try_iter().collect()
    }
}

fn worker_loop(commands: Receiver<Command>, events: mpsc::Sender<Event>) {
    let mut session: Option<ProfileSession> = None;
    while let Ok(command) = commands.recv() {
        match handle_command(&mut session, command) {
            Err(error) => {
                eprintln!(
                    "safechat UI {} operation failed: {:#}",
                    error.operation, error.source
                );
                let _ = events.send(Event::Error {
                    operation: error.operation,
                    message: "operation failed; see the application log for details".to_owned(),
                });
            }
            Ok(Some(event)) => {
                let _ = events.send(event);
            }
            Ok(None) => {}
        }
    }
}
