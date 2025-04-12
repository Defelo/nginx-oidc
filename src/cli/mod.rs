use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::CompleteEnv;
use serve::ServeCommand;

mod serve;

pub async fn main() -> anyhow::Result<()> {
    CompleteEnv::with_factory(Cli::command).complete();

    let cli = Cli::parse();

    tracing_subscriber::fmt::init();

    match cli.command {
        Command::Serve(cmd) => cmd.invoke().await,
    }
}

#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the HTTP API server
    Serve(ServeCommand),
}
