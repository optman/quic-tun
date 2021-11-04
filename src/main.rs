use anyhow::Result;
use structopt::StructOpt;

mod client;
mod config;
use client::{run_client, ClientOpt};
mod server;
use server::{run_server, ServerOpt};
mod common;
use common::{daemonize, gen_cert};

#[derive(StructOpt, Debug)]
#[structopt(name = "quic-tun")]
enum Opt {
    Client(ClientOpt),
    Server(ServerOpt),
    #[structopt(name = "gencert")]
    GenCert,
}

fn main() {
    let opt: Opt = StructOpt::from_args();

    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    run(opt).unwrap();
}

fn run(opt: Opt) -> Result<()> {
    match opt {
        Opt::Client(opt) => {
            if opt.daemonize {
                daemonize();
            }
            run_client(opt)
        }
        Opt::Server(opt) => {
            if opt.daemonize {
                daemonize();
            }
            run_server(opt)
        }
        Opt::GenCert => gen_cert(),
    }
}
