#![no_std]
#![no_main]

use core::hash;
use core::hash::Hash;
use core::hash::Hasher;
use core::mem;

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::SockHash;
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::info;
use aya_log_ebpf::log;
use fnv::FnvHasher;
use memcrs_common::network::RequestHeader;
use memcrs_common::network::MAGIC_REQUEST;
use memcrs_common::network::OPCODE_GET;
use memcrs_common::{EbpfKey, EbpfValue};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

const MEMCACHED_BIN_HEADER_LEN: usize = core::mem::size_of::<RequestHeader>();

static MAX_ENTRIES: u32 = 1024 * 1024;

// Memcached response for successful SET
const STORED_REPLY: [u8; 8] = *b"STORED\r\n";
// Memcached response for successful GET of an empty item
const END_REPLY: [u8; 5] = *b"END\r\n";

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

#[map]
static SOCK_MAP: SockHash<u32> = SockHash::with_max_entries(1024, 0);

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
    let ipv4_header_len = (unsafe { (*ipv4hdr).ihl() } as usize);
    let transport_header_offset = EthHdr::LEN + ipv4_header_len;

    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).dst_addr });

    let (source_port, dest_port, payload_offset) = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, transport_header_offset)?;
            let tcp_header_len = TcpHdr::LEN;

            let payload_offset = transport_header_offset + tcp_header_len;
            let source_port = u16::from_be_bytes(unsafe { (*tcphdr).source });
            let dest_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });

            (source_port, dest_port, payload_offset)
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, transport_header_offset)?;
            let udp_header_len = UdpHdr::LEN;

            let payload_offset = transport_header_offset + udp_header_len;
            let source_port = unsafe { (*udphdr).src_port() };
            let dest_port = unsafe { (*udphdr).dst_port() };

            // (source_port, dest_port, payload_offset)
            return Ok(xdp_action::XDP_PASS); // Ignore UDP packets for now
        }
        _ => return Err(()),
    };

    let map_port_ref = CONFIG_PORT.get(0);
    let memcached_port: u16 = match map_port_ref {
        Some(port_value) => (*port_value) as u16,
        None => 11211,
    };

    if dest_port != memcached_port {
        return Ok(xdp_action::XDP_PASS); // Ignore packets not destined for memcached port
    }

    let payload_len = ctx.data_end() - (ctx.data() + payload_offset);
    if payload_len < MEMCACHED_BIN_HEADER_LEN {
        info!(
            &ctx,
            "XDP: Packet too short for memcached header: {} bytes", payload_len
        );
        return Ok(xdp_action::XDP_PASS); // Ignore packets that are too short to contain memcached header
    }

    let req_hdr: *const RequestHeader = ptr_at(&ctx, payload_offset)?;

    let is_binary_request = unsafe { (*req_hdr).magic == MAGIC_REQUEST };
    let is_get_command = unsafe { (*req_hdr).opcode == OPCODE_GET };

    info!(
        &ctx,
        "XDP: Packet from {}:{} to {}:{} - Payload Length: {} bytes",
        source_addr,
        source_port,
        dest_addr,
        dest_port,
        payload_len
    );

    if is_binary_request && is_get_command {
        info!(
            &ctx,
            "XDP: Detected Binary TCP GET (Opcode: {}) on port {}", OPCODE_GET, dest_port
        );
    }

    // hash the header fields to create the key
    // hash_key(
    //     &ctx,
    //     0, // start from the beginning of the Ethernet header
    //     payload_offset + CMD_LEN, // include up to the end of the command
    // );

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

fn hash_key(ctx: &XdpContext, key_start_offset: usize, key_len: usize) -> EbpfKey {
    let data_slice: &[u8] = unsafe {
        let start = ctx.data() + key_start_offset;
        core::slice::from_raw_parts(start as *const u8, key_len)
    };

    let mut hasher = FnvHasher::default();
    data_slice.hash(&mut hasher);
    hasher.finish()
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
