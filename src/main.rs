use anyhow::{Context, Result};
use std::str;

// Usage: your_docker.sh run <image> <command> <arg1> <arg2> ...
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let command = &args[3];
    let command_args = &args[4..];
    let output = std::process::Command::new(command)
        .args(command_args)
        .output()
        .with_context(|| {
            format!(
                "Tried to run '{}' with arguments {:?}",
                command, command_args
            )
        })?;

    let stdout_contents = str::from_utf8(output.stdout.as_slice())?;
    let stderr_contents = str::from_utf8(output.stderr.as_slice())?;

    print!("{}", stdout_contents);
    eprint!("{}", stderr_contents);

    if !output.status.success() || output.status.code().unwrap() == 1 {
        std::process::exit(1);
    }

    Ok(())
}
