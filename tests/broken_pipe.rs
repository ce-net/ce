//! Regression: the `ce` process must NOT panic when a write to stdout/stderr fails.
//!
//! Two real-world triggers, same root cause (the `println!`/`eprintln!` macros panic on any write
//! error):
//!   - broken pipe: `ce status | head` — the reader closes early, the next stdout write gets EPIPE.
//!   - disk full: a daemon logging line hits ENOSPC (observed live:
//!     "failed printing to stderr: No space left on device (os error 28)", which killed a
//!     tokio-rt-worker and took the node down).
//!
//! A daemon that dies because a log write failed is not infrastructure. This test reproduces the
//! broken-pipe variant deterministically against the real binary: it must exit cleanly (conventional
//! SIGPIPE termination), never emitting a Rust panic ("failed printing" / "panicked").
//!
//! Reproduce-first (project rule): before the fix this FAILS (the child prints the panic); after the
//! SIGPIPE-default fix it passes.

use std::io::Read;
use std::process::{Command, Stdio};

#[cfg(unix)]
#[test]
fn cli_does_not_panic_on_broken_stdout_pipe() {
    let tmp = std::env::temp_dir().join(format!("ce-bp-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);

    // `ce id` is offline and writes several lines to stdout via println!. Close the read end of its
    // stdout pipe immediately so its writes hit a broken pipe.
    let mut child = Command::new(env!("CARGO_BIN_EXE_ce"))
        .arg("--data-dir")
        .arg(&tmp)
        .arg("id")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ce id");

    // Drop the read end → the child's stdout is now a broken pipe.
    drop(child.stdout.take());

    let mut stderr = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut stderr);
    }
    let status = child.wait().expect("wait ce id");

    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        !stderr.contains("failed printing") && !stderr.contains("panicked"),
        "ce panicked on a broken stdout pipe instead of exiting cleanly.\n\
         exit: {status:?}\nstderr:\n{stderr}"
    );
}
