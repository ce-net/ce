use anyhow::Result;
use ce_chain::Chain;
use ce_identity::Identity;
use ce_node::{Node, NodeConfig};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "ce", about = "CE node")]
struct Cli {
    #[arg(long, help = "Override data directory (default: ~/.local/share/ce)")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the CE node: mine, meter, mesh, and HTTP API.
    Start {
        #[arg(short, long, default_value = "4001")]
        port: u16,
        #[arg(long, default_value = "8080")]
        api_port: u16,
        /// Bootstrap peer multiaddrs: /ip4/1.2.3.4/tcp/4001/p2p/<peer-id>
        #[arg(short, long)]
        bootstrap: Vec<String>,
    },
    /// Show this node's credit balance.
    Balance,
    /// Show node status (id, chain height, difficulty, balance).
    Status,
    /// Print this node's ID.
    Id,
}

fn data_dir(override_path: Option<PathBuf>) -> PathBuf {
    override_path.unwrap_or_else(|| {
        ProjectDirs::from("", "", "ce")
            .map(|d| d.data_dir().to_owned())
            .unwrap_or_else(|| PathBuf::from(".ce"))
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("ce=info".parse()?))
        .init();

    let cli = Cli::parse();
    let data_dir = data_dir(cli.data_dir);

    match cli.command {
        Commands::Start { port, api_port, bootstrap } => {
            let config = NodeConfig {
                listen_port: port,
                bootstrap_peers: bootstrap,
                data_dir,
                api_port,
                mine: true,
                ..Default::default()
            };
            let node = Node::start(config).await?;
            let status = node.status().await;
            println!("CE node running");
            println!("  node id  : {}", status.node_id);
            println!("  height   : {}", status.height);
            println!("  balance  : {}", status.balance);
            println!("  p2p port : {}", status.listen_port);
            println!("  api port : {}", status.api_port);
            println!("Press Ctrl-C to stop.");
            tokio::signal::ctrl_c().await?;
            println!("Shutting down.");
        }

        Commands::Balance => {
            let identity_dir = data_dir.join("identity");
            let chain_path = data_dir.join("chain").join("chain.json");
            let identity = Identity::load_or_generate(&identity_dir)?;
            let chain = Chain::load_or_genesis(&chain_path);
            println!("{}", chain.balance(&identity.node_id()));
        }

        Commands::Status => {
            let identity_dir = data_dir.join("identity");
            let chain_path = data_dir.join("chain").join("chain.json");
            let identity = Identity::load_or_generate(&identity_dir)?;
            let chain = Chain::load_or_genesis(&chain_path);
            println!("node id   : {}", identity.node_id_hex());
            println!("height    : {}", chain.height());
            println!("difficulty: {}", chain.difficulty);
            println!("balance   : {}", chain.balance(&identity.node_id()));
        }

        Commands::Id => {
            let identity_dir = data_dir.join("identity");
            let identity = Identity::load_or_generate(&identity_dir)?;
            println!("{}", identity.node_id_hex());
        }
    }

    Ok(())
}
