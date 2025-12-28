//! Configuration file watching with automatic reload
//!
//! Monitors the config file for changes and triggers reload after debouncing.

use notify::RecursiveMode;
use notify_debouncer_mini::{new_debouncer, DebouncedEvent, Debouncer};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;

/// File watcher for configuration reload
///
/// Monitors the config file and sends reload signals when changes are detected.
/// Uses 1-second debouncing to handle multiple rapid writes (e.g., editors saving
/// temporary files).
pub struct ConfigWatcher {
    _debouncer: Debouncer<notify::RecommendedWatcher>,
    config_path: PathBuf,
}

impl ConfigWatcher {
    /// Start watching the config file
    ///
    /// # Arguments
    /// * `config_path` - Path to config file to watch
    /// * `reload_tx` - Channel to send reload signals
    /// * `saving_flag` - Atomic flag to ignore events during programmatic saves
    ///
    /// # Errors
    /// Returns error if file watching cannot be initialized
    pub fn new(
        config_path: PathBuf,
        reload_tx: mpsc::UnboundedSender<()>,
        saving_flag: Arc<AtomicBool>,
    ) -> Result<Self, notify::Error> {
        let path_for_closure = config_path.clone();
        let saving_flag_clone = Arc::clone(&saving_flag);
        
        // Create debounced watcher with 1-second timeout
        let (tx, rx) = std::sync::mpsc::channel();
        let mut debouncer = new_debouncer(Duration::from_secs(1), tx)?;
        
        // Watch only the specific config file (NonRecursive)
        debouncer
            .watcher()
            .watch(&config_path, RecursiveMode::NonRecursive)?;
        
        log::info!("Started watching config file: {:?}", config_path);
        
        // Spawn background task to process debounced events
        tokio::spawn(async move {
            loop {
                match rx.recv() {
                    Ok(Ok(events)) => {
                        // Check if any event affects our config file
                        // AND we're not currently saving (prevents self-trigger)
                        if Self::is_config_modified(&events, &path_for_closure, &saving_flag_clone) {
                            log::info!("External config file change detected, triggering reload");
                            if reload_tx.send(()).is_err() {
                                log::error!("Failed to send reload signal - receiver dropped");
                                break;
                            }
                        }
                    }
                    Ok(Err(error)) => {
                        log::error!("File watch error: {:?}", error);
                    }
                    Err(_) => {
                        log::info!("File watcher channel closed");
                        break;
                    }
                }
            }
        });
        
        Ok(Self {
            _debouncer: debouncer,
            config_path,
        })
    }
    
    /// Check if debounced events contain modifications to our config file
    ///
    /// Returns false if we're currently performing a programmatic save,
    /// preventing self-trigger reload loop.
    fn is_config_modified(
        events: &[DebouncedEvent],
        config_path: &PathBuf,
        saving_flag: &Arc<AtomicBool>,
    ) -> bool {
        // Ignore ALL events if we're currently saving
        // This prevents self-trigger reload loop (Race #2)
        if saving_flag.load(Ordering::SeqCst) {
            log::trace!("Ignoring file events during programmatic save");
            return false;
        }
        
        // Check if any event affects our config file
        events.iter().any(|event| {
            // Any event for our config file should trigger reload
            // DebouncedEventKind can be Any or AnyContinuous
            event.path == *config_path
        })
    }
}

impl Drop for ConfigWatcher {
    fn drop(&mut self) {
        log::info!("Stopping config file watcher for {:?}", self.config_path);
    }
}
