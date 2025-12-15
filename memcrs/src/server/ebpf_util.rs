use std::{
    fs::{self, File},
    io::Write,
};

use anyhow::{Context, Result};
use aya::{
    maps::{sock::SockMapFd, Array, HashMap, MapData, SockHash},
    programs::{CgroupAttachMode, SkSkb, SockOps, Xdp, XdpFlags},
    Ebpf,
};
use memcrs_common::{EbpfKey, EbpfValue, SockKey};

pub fn add_self_to_cgroup(cgroup_path: &str) -> Result<()> {
    std::fs::create_dir_all(cgroup_path)
        .context(format!("Failed to create cgroup directory {}", cgroup_path))?;

    let current_pid = std::process::id();
    let procs_path = format!("{}/cgroup.procs", cgroup_path);

    let mut procs_file = fs::OpenOptions::new()
        .write(true)
        .open(&procs_path)
        .context(format!(
            "Failed to open {} for PID migration. Ensure root permissions.",
            procs_path
        ))?;

    procs_file
        .write_all(format!("{}", current_pid).as_bytes())
        .context("Failed to write PID to cgroup.procs")?;

    Ok(())
}

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

pub fn get_sock_map(ebpf: &mut Ebpf, map_name: &str) -> Result<SockHash<MapData, SockKey>> {
    let map_handle = ebpf
        .take_map(map_name)
        .context(format!("eBPF map '{}' not found", map_name))?;

    let sock_map: SockHash<MapData, SockKey> = map_handle
        .try_into()
        .context("Failed to convert map handle to HashMap<u32, u32>")?;

    Ok(sock_map)
}

/// Sets the port configuration in the specified eBPF map
pub fn set_port_config(ebpf: &mut Ebpf, map_name: &str, port: u16) -> Result<()> {
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

/// Retrieves the sock ops program from the eBPF object
pub fn get_sock_ops_program<'a>(ebpf: &'a mut Ebpf, program_name: &str) -> Result<&'a mut SockOps> {
    let program = ebpf
        .program_mut(program_name)
        .context(format!(
            "Sock ops program '{}' not found in eBPF object",
            program_name
        ))?
        .try_into()
        .context(format!(
            "Failed to cast program '{}' to SockOps type",
            program_name
        ))?;

    Ok(program)
}

/// Load and attach the sock ops program
pub fn attach_sock_ops_program(program: &mut SockOps, cgroup: &File) -> Result<()> {
    program
        .load()
        .context("Failed to load sock ops program into kernel")?;

    program
        .attach(cgroup, CgroupAttachMode::Single)
        .context("Failed to attach sock ops program to cgroup")?;

    Ok(())
}

pub fn attach_skb_programs(
    ebpf: &mut Ebpf,
    parser_name: &str,
    verdict_name: &str,
    sock_map: &SockMapFd,
) -> Result<()> {
    let parser_program: &mut SkSkb = ebpf
        .program_mut(parser_name)
        .context(format!(
            "Stream Parser program '{}' not found in eBPF object",
            parser_name
        ))?
        .try_into()
        .context(format!(
            "Failed to cast program '{}' to Skb type",
            parser_name
        ))?;

    parser_program
        .load()
        .context("Failed to load parser program into kernel")?;

    parser_program
        .attach(sock_map)
        .context("Failed to attach parser program to sock map")?;

    let verdict_program: &mut SkSkb = ebpf
        .program_mut(verdict_name)
        .context(format!(
            "Stream Verdict program '{}' not found in eBPF object",
            verdict_name
        ))?
        .try_into()
        .context(format!(
            "Failed to cast program '{}' to Skb type",
            verdict_name
        ))?;

    verdict_program
        .load()
        .context("Failed to load verdict program into kernel")?;

    verdict_program
        .attach(sock_map)
        .context("Failed to attach verdict program to sock map")?;

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
