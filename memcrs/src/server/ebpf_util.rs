use anyhow::{Context, Result};
use aya::{
    Ebpf, maps::{Array, HashMap, MapData}, programs::{Xdp, XdpFlags}
};
use memcrs_common::{EbpfKey, EbpfValue};

/// Retrieves the cache map from the eBPF object
pub fn get_cache_map(
    ebpf: &mut Ebpf,
    map_name: &str,
) -> Result<HashMap<MapData, EbpfKey, EbpfValue>> {
    let map_handle = ebpf
        .take_map(map_name)
        .context(format!("eBPF map '{}' not found", map_name))?;

    let cache_map = map_handle
        .try_into()
        .context("Failed to convert map handle to HashMap<EbpfKey, EbpfValue>")?;

    Ok(cache_map)
}

/// Sets the port configuration in the specified eBPF map
pub fn set_port_config(
    ebpf: &mut Ebpf,
    map_name: &str,
    port: u16,
) -> Result<()> {
    let map_handle = ebpf
        .map_mut(map_name)
        .context(format!("eBPF map '{}' not found", map_name))?;

    let mut port_map: Array<_, u32> = map_handle
        .try_into()
        .context("Failed to convert map handle to Array<u32>")?;

    port_map
        .set(0, u32::from(port), 0)
        .context("Failed to set port in configuration map")?;

    Ok(())
}

/// Retrieves the XDP program from the eBPF object
pub fn get_xdp_program<'a>(ebpf: &'a mut Ebpf, program_name: &str) -> Result<&'a mut Xdp> {
    let program = ebpf
        .program_mut(program_name)
        .context(format!(
            "XDP program '{}' not found in eBPF object",
            program_name
        ))?
        .try_into()
        .context(format!(
            "Failed to cast program '{}' to Xdp type",
            program_name
        ))?;

    Ok(program)
}

/// Loads and attaches the XDP program to the specified network interface
pub fn attach_xdp_program(program: &mut Xdp, interface_name: &str) -> Result<()> {
    program
        .load()
        .context("Failed to load XDP program into kernel")?;

    program
        .attach(interface_name, XdpFlags::default())
        .context(format!(
            "Failed to attach XDP program to interface: {}",
            interface_name
        ))?;

    Ok(())
}

/// Initializes the eBPF logger
pub fn init_ebpf_logger(ebpf: &mut Ebpf) {
    match aya_log::EbpfLogger::init(ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("Failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)
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
}
