use std::{
    os::unix::prelude::FileTypeExt,
    path::{Path, PathBuf},
    process::exit,
};

use anyhow::Result;
use clap::Parser as _;

use ssh_rev::{Exec, RevAgent, RevExec};

#[derive(clap::Parser, Debug)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    Agent(CmdAgent),
    Exec(CmdExec),
}

#[derive(clap::Args, Debug)]
struct CmdAgent {
    #[clap(env, long, short = 'A')]
    ssh_auth_sock: Option<PathBuf>,
    #[clap(long, short = 'R')]
    ssh_rev_sock: PathBuf,
}

#[derive(clap::Args, Debug)]
struct CmdExec {
    #[clap(env, long, short = 'A')]
    ssh_auth_sock: PathBuf,
    #[clap(long, short)]
    env: Vec<String>,
    #[clap(long, short = 'C')]
    cwd: Option<String>,
    cmd: String,
    args: Vec<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Agent(agent) => {
            env_logger::init();
            cleanup_sock(&agent.ssh_rev_sock)?;
            let rev_agent = RevAgent::open(&agent.ssh_rev_sock, agent.ssh_auth_sock)?;
            rev_agent.run().await?;
        }
        Command::Exec(exec) => {
            let rev_exec = RevExec::open(&exec.ssh_auth_sock).await?;
            let exec = Exec {
                cmd: exec.cmd,
                args: exec.args,
                envs: Default::default(),
                cwd: exec.cwd,
            };
            let stdin = tokio::io::stdin();
            let stdout = tokio::io::stdout();
            let stderr = tokio::io::stderr();
            let exit_code = rev_exec.exec(exec, stdin, stdout, stderr).await?;
            exit(exit_code);
        }
    }
    Ok(())
}

fn cleanup_sock(path: &Path) -> Result<()> {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => Ok(std::fs::remove_file(path)?),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}
