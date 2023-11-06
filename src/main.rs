use std::ffi::CString;
use std::process::Output;
use std::str;

use anyhow::{Context, Result};

// Usage: your_docker.sh run <image> <command> <arg1> <arg2> ...

fn main() -> Result<()> {
    setup_chroot_jail();
    let args: Vec<_> = std::env::args().collect();
    let command = &args[3];
    let command_args = &args[4..];
    let output = exec_command_and_get_output(command, &Vec::from(command_args))?;

    let stdout_contents = str::from_utf8(output.stdout.as_slice())?;
    let stderr_contents = str::from_utf8(output.stderr.as_slice())?;

    print!("{}", stdout_contents);
    eprint!("{}", stderr_contents);

    let child_exit_code = output.status.code().unwrap();
    if !output.status.success() {
        std::process::exit(child_exit_code);
    }

    Ok(())
}

fn setup_chroot_jail() {
    // TODO(sudo-nan0_RaySK): Fix this heap allocation and cloning of these args later
    let jail_dir = String::from("jail");
    let _ = exec_command_and_get_output("mkdir", &vec![jail_dir.clone()]);
    _ = exec_command_and_get_output("cp",
                                    &vec![
                                        String::from("-r"),
                                        String::from("/lib"),
                                        jail_dir.clone(),
                                    ]);
    _ = exec_command_and_get_output("cp",
                                    &vec![
                                        String::from("-r"),
                                        String::from("/usr/lib"),
                                        jail_dir.clone(),
                                    ]);
    _ = exec_command_and_get_output("cp",
                                    &vec![
                                        String::from("-r"),
                                        String::from("/bin"),
                                        jail_dir.clone(),
                                    ]);
    _ = exec_command_and_get_output("cp",
                                    &vec![
                                        String::from("/usr/bin/file"),
                                        jail_dir.clone(),
                                    ]);
    _ = exec_command_and_get_output("mkdir",
                                    &vec![
                                        String::from("-p"),
                                        String::from("jail/usr/local/bin"),
                                    ]);
    _ = exec_command_and_get_output("cp",
                                    &vec![
                                        String::from("/usr/local/bin/docker-explorer"),
                                        String::from("jail/usr/local/bin"),
                                    ]);
    _ = exec_command_and_get_output("mkdir", &vec![String::from("jail/proc")]);
    _ = exec_command_and_get_output("mkdir", &vec![String::from("jail/dev")]);
    _ = exec_command_and_get_output("touch", &vec![String::from("jail/dev/null")]);
    _ = exec_command_and_get_output("chmod",
                                    &vec![
                                        String::from("666"),
                                        String::from("jail/dev/null"),
                                    ]);
    _ = exec_command_and_get_output("mount",
                                    &vec![
                                        String::from("-B"),
                                        String::from("/proc"),
                                        String::from("jail/proc"),
                                    ]);
    // Setting up `chroot` jail
    let jail_path = CString::new("jail").unwrap();
    unsafe {
        let exit_code = libc::chroot(jail_path.as_ptr());
        if !(exit_code == 0i32) {
            eprintln!("Error executing libc::chroot('jail'), exit code => {:?}", exit_code);
            std::process::exit(exit_code as i32);
        }
        let exit_code = libc::chdir(jail_path.as_ptr());
        if !(exit_code == 0i32) {
            eprintln!("Error executing libc::chdir('jail'), exit code => {:?}", exit_code);
            std::process::exit(exit_code as i32);
        }
    }
}

fn exec_command_and_get_output(command: &str, args: &Vec<String>) -> Result<Output> {
    std::process::Command::new(command).args(args).output().with_context(|| {
        format!(
            "Tried to run '{}' with arguments {:?}",
            command, args
        )
    })
}