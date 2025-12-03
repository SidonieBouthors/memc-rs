use std::env;
extern crate memcrs;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    memcrs::server::main::run(env::args().collect()).await
}
