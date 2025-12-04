#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::info;
use memcrs_common::{EbpfKey, EbpfValue};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

static MAX_ENTRIES: u32 = 1024 * 1024;

#[map]
static CACHE_MAP: HashMap<EbpfKey, EbpfValue> = HashMap::with_max_entries(
    MAX_ENTRIES,
    0, // flags
);

#[map]
static CONFIG_PORT: Array<u32> = Array::with_max_entries(
    1, // single port value
    0, // flags
);

#[xdp]
pub fn xdp_packet_capture(ctx: XdpContext) -> u32 {
    match try_xdp_packet_capture(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_packet_capture(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS), // Ignore non-IPv4 packets
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be_bytes(unsafe { (*tcphdr).source })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe { (*udphdr).src_port() }
        }
        _ => return Err(()),
    };

    let map_port_ref = CONFIG_PORT.get(0);
    let memcached_port: u16 = match map_port_ref {
        Some(port_value) => (*port_value) as u16,
        None => 11211,
    };

    if source_port != memcached_port {
        return Ok(xdp_action::XDP_PASS); // Ignore packets not destined for memcached port
    }

    info!(&ctx, "SRC IP: {:i}, SRC PORT: {}", source_addr, source_port);

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
