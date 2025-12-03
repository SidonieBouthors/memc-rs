use crate::cache::cache::Cache;
use crate::memcache;
use crate::memcache_server;
use crate::memory_store::dash_map_store::DashMapMemoryStore;
use crate::memory_store::ebpf_map_store::EbpfMapMemoryStore;
use crate::memory_store::moka_store::MokaMemoryStore;
use crate::memory_store::StoreEngine;
use crate::server::timer;
use aya::maps::HashMap;
use log::info;
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

pub fn run(args: Vec<String>) {
    env_logger::init();
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

            match aya_log::EbpfLogger::init(&mut ebpf) {
                Err(e) => {
                    // This can happen if you remove all log statements from your eBPF program.
                    warn!("failed to initialize eBPF logger: {e}");
                }
                Ok(logger) => {
                    let mut logger = tokio::io::unix::AsyncFd::with_interest(
                        logger,
                        tokio::io::Interest::READABLE,
                    )
                    .unwrap();
                    tokio::task::spawn(async move {
                        loop {
                            let mut guard = logger.readable_mut().await.unwrap();
                            guard.get_inner_mut().flush();
                            guard.clear_ready();
                        }
                    });
                }
            }

            // let memory: Storage = HashMap::try_from(ebpf.map_mut("CACHE_MAP").unwrap())?;

            let map_handle = ebpf
                .take_map("CACHE_MAP")
                .ok_or_else(|| {
                    eprintln!("Fatal: eBPF map 'CACHE_MAP' not found");
                    process::exit(1);
                })
                .and_then(|m| {
                    HashMap::try_from(m).map_err(|e| {
                        eprintln!("Fatal: Failed to create map handle: {}", e);
                        process::exit(1);
                    })
                })
                .unwrap();

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

    let parent_runtime = memcache_server::runtime_builder::create_memcrs_server(cli_config, store);
    parent_runtime.block_on(system_timer.run())
}
