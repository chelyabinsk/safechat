//! Serialized command execution and event delivery.

use super::{Command, Event, ProfileSession, ServicePorts, handle_command};
use anyhow::Result;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;

const COMMAND_QUEUE_SIZE: usize = 16;

pub struct UiService {
    commands: SyncSender<Command>,
    events: Arc<Mutex<Receiver<Event>>>,
    ports: Arc<ServicePorts>,
    debug: bool,
}

impl UiService {
    pub fn new() -> Self {
        Self::new_with_debug(false)
    }

    pub fn new_with_debug(debug: bool) -> Self {
        Self::with_ports_and_debug(ServicePorts::production(), debug)
    }

    pub fn with_ports(ports: ServicePorts) -> Self {
        Self::with_ports_and_debug(ports, false)
    }

    fn with_ports_and_debug(ports: ServicePorts, debug: bool) -> Self {
        let (commands, command_rx) = mpsc::sync_channel(COMMAND_QUEUE_SIZE);
        let (event_tx, event_rx) = mpsc::channel();
        let ports = Arc::new(ports);
        let worker_ports = Arc::clone(&ports);
        thread::spawn(move || worker_loop(command_rx, event_tx, worker_ports, debug));
        Self {
            commands,
            events: Arc::new(Mutex::new(event_rx)),
            ports,
            debug,
        }
    }

    pub fn available_profiles(&self) -> Result<Vec<String>> {
        self.ports.profile.available_profiles()
    }

    pub fn transport_options(&self) -> Vec<String> {
        self.ports.transport.options()
    }

    pub fn parse_transport(&self, value: &str) -> Option<super::TransportKind> {
        self.ports.transport.parse(value)
    }

    /// Clipboard access stays on the caller thread because Wayland clipboard
    /// ownership is serviced by the application event loop.
    pub fn copy_text(&self, text: &str) -> Result<()> {
        self.ports.clipboard.set_text(text)
    }

    pub fn submit(&self, command: Command) -> Result<()> {
        let operation = command.operation();
        eprintln_if_debug(
            self.debug,
            format_args!("queued {operation} operation via submit()"),
        );
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                TrySendError::Full(_) => anyhow::anyhow!("client operation queue is busy"),
                TrySendError::Disconnected(_) => anyhow::anyhow!("client worker stopped"),
            })
    }

    pub fn try_submit(&self, command: Command) -> bool {
        let operation = command.operation();
        let accepted = self.commands.try_send(command).is_ok();
        eprintln_if_debug(
            self.debug,
            format_args!("poll {operation} operation queue accepted={accepted}"),
        );
        accepted
    }

    pub fn drain_events(&self) -> Vec<Event> {
        let Ok(events) = self.events.lock() else {
            return Vec::new();
        };
        events.try_iter().collect()
    }
}

fn eprintln_if_debug(debug: bool, message: std::fmt::Arguments<'_>) {
    if debug {
        eprintln!("safechat debug: {message}");
    }
}

fn worker_loop(
    commands: Receiver<Command>,
    events: mpsc::Sender<Event>,
    ports: Arc<ServicePorts>,
    debug: bool,
) {
    let mut session: Option<ProfileSession> = None;
    if debug {
        eprintln!("safechat debug: UI worker started");
    }
    while let Ok(command) = commands.recv() {
        let operation = command.operation();
        if debug {
            eprintln!("safechat debug: starting {operation} operation");
        }
        match handle_command(&mut session, command, &ports) {
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
                if debug {
                    eprintln!(
                        "safechat debug: completed {operation} operation; sending {} event",
                        event.kind()
                    );
                }
                let _ = events.send(event);
            }
            Ok(None) => {
                if debug {
                    eprintln!("safechat debug: completed {operation} operation");
                }
            }
        }
    }
    if debug {
        eprintln!("safechat debug: UI worker stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::UiService;
    use crate::ui_service::ports::Clipboard;
    use crate::ui_service::{Command, Event, Operation, ServicePorts};
    use anyhow::Result;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    struct RecordingClipboard(Mutex<Vec<String>>);

    impl Clipboard for RecordingClipboard {
        fn set_text(&self, text: &str) -> Result<()> {
            self.0.lock().unwrap().push(text.to_owned());
            Ok(())
        }
    }

    #[test]
    fn worker_reports_sanitized_errors_for_commands_without_a_session() {
        let service = UiService::new();
        service
            .submit(Command::LoadHistory {
                peer: "not-a-bundle".to_owned(),
            })
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            for event in service.drain_events() {
                if let Event::Error { operation, message } = event {
                    assert_eq!(operation, Operation::History);
                    assert_eq!(
                        message,
                        "operation failed; see the application log for details"
                    );
                    return;
                }
            }
            assert!(Instant::now() < deadline, "worker did not return an error");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn worker_uses_injected_clipboard_port() {
        let clipboard = Arc::new(RecordingClipboard(Mutex::new(Vec::new())));
        let mut ports = ServicePorts::production();
        ports.clipboard = clipboard.clone();
        let service = UiService::with_ports(ports);
        service.copy_text("ciphertext").unwrap();
        assert_eq!(clipboard.0.lock().unwrap().as_slice(), ["ciphertext"]);
    }
}
