use crate::cache::cache::Cache;
use crate::memcache;
use crate::memcache_server;
use crate::memory_store::dash_map_store::DashMapMemoryStore;
use crate::memory_store::ebpf_map_store::EbpfMapMemoryStore;
use crate::memory_store::moka_store::MokaMemoryStore;
use crate::memory_store::StoreEngine;
use crate::server::ebpf_util::attach_xdp_program;
use crate::server::ebpf_util::get_cache_map;
use crate::server::ebpf_util::get_xdp_program;
use crate::server::ebpf_util::init_ebpf_logger;
use crate::server::ebpf_util::set_port_config;
use crate::server::timer;
use anyhow::Context;
use anyhow::Error;
use aya::programs::Xdp;
use network_interface::NetworkInterface;
use network_interface::NetworkInterfaceConfig;
use std::net::IpAddr;
use std::process;
use std::sync::Arc;
use tracing_log::LogTracer;
extern crate clap;

#[cfg(feature = "jemallocator")]
use jemallocator::Jemalloc;

#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn get_log_level(verbose: u8) -> tracing::Level {
    // Vary the output based on how many times the user used the "verbose" flag
    // // (i.e. 'myprog -v -v -v' or 'myprog -vvv' vs 'myprog -v'
    match verbose {
        0 => tracing::Level::ERROR,
        1 => tracing::Level::WARN,
        2 => tracing::Level::INFO,
        3 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    }
}

pub async fn run(args: Vec<String>) -> anyhow::Result<()> {
    LogTracer::init().expect("Cannot initialize logger");

    let cli_config = match memcache::cli::parser::parse(args) {
        Ok(config) => config,
        Err(err) => {
            eprint!("{}", err);
            process::exit(1);
        }
    };
    // Vary the output based on how many times the user used the "verbose" flag
    // (i.e. 'myprog -v -v -v' or 'myprog -vvv' vs 'myprog -v'
    tracing_subscriber::fmt()
        .with_max_level(get_log_level(cli_config.verbose))
        .init();

    info!("Listen address: {}", cli_config.listen_address);
    info!("Listen port: {}", cli_config.port);
    info!("Connection limit: {}", cli_config.connection_limit);
    info!("Number of threads: {}", cli_config.threads);
    info!("Store engine: {}", cli_config.store_engine.as_str());
    info!("Eviction policy: {}", cli_config.eviction_policy.as_str());
    info!("Runtime type: {}", cli_config.runtime_type.as_str());
    info!(
        "Max item size: {}",
        byte_unit::Byte::from_u64(cli_config.item_size_limit)
            .get_appropriate_unit(byte_unit::UnitType::Decimal)
    );
    info!(
        "Memory limit: {}",
        byte_unit::Byte::from_u64(cli_config.memory_limit)
            .get_appropriate_unit(byte_unit::UnitType::Decimal)
    );

    let system_timer: Arc<timer::SystemTimer> = Arc::new(timer::SystemTimer::new());

    let store: Arc<dyn Cache + Send + Sync> = match cli_config.store_engine {
        StoreEngine::EbpfMap => {
            // Bump the memlock rlimit. This is needed for older kernels that don't use the
            // new memcg based accounting, see https://lwn.net/Articles/837122/
            let rlim = libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            };
            let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
            if ret != 0 {
                debug!("remove limit on locked memory failed, ret is: {ret}");
            }

            // This will include your eBPF object file as raw bytes at compile-time and load it at
            // runtime. This approach is recommended for most real-world use cases. If you would
            // like to specify the eBPF program at runtime rather than at compile-time, you can
            // reach for `Bpf::load_file` instead.
            let mut ebpf = match aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/memcrs"
            ))) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Fatal: Failed to load eBPF program: {}", e);
                    process::exit(1);
                }
            };

            init_ebpf_logger(&mut ebpf);

            set_port_config(&mut ebpf, "CONFIG_PORT", cli_config.port)?;

            let interface_name = get_interface_name_from_addr(cli_config.listen_address)?;
            let program: &mut Xdp = get_xdp_program(&mut ebpf, "xdp_packet_capture")?;
            attach_xdp_program(program, &interface_name)?;

            let map_handle = get_cache_map(&mut ebpf, "CACHE_MAP")?;

            Arc::new(EbpfMapMemoryStore::new(
                system_timer.clone(),
                ebpf,
                map_handle,
            ))
        }
        StoreEngine::DashMap => Arc::new(DashMapMemoryStore::new(system_timer.clone())),
        StoreEngine::Moka => Arc::new(MokaMemoryStore::new(
            system_timer.clone(),
            cli_config.memory_limit,
        )),
    };

    let server_future = memcache_server::runtime_builder::create_memcrs_server(cli_config, store);

    tokio::try_join!(server_future, system_timer.run(),)?;

    Ok(())
}

fn get_interface_name_from_addr(target_addr: IpAddr) -> anyhow::Result<String> {
    let interfaces = NetworkInterface::show().context("Failed to retrieve network interfaces")?;

    for interface in interfaces {
        for addr in interface.addr {
            if addr.ip() == target_addr {
                return Ok(interface.name);
            }
        }
    }
    Err(Error::msg(format!(
        "No network interface found with IP address: {}",
        target_addr
    )))
}
