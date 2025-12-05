#![no_std]
#![no_main]

use core::hash;
use core::hash::Hash;
use core::hash::Hasher;
use core::mem;

use aya_ebpf::bindings::sk_action;
use aya_ebpf::bindings::BPF_ANY;
use aya_ebpf::bindings::BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB;
use aya_ebpf::bindings::BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::macros::{sk_msg, sock_ops};
use aya_ebpf::maps::SockHash;
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::programs::SkMsgContext;
use aya_ebpf::programs::SockOpsContext;
use aya_ebpf::programs::XdpContext;
use aya_ebpf::EbpfContext;
use aya_log_ebpf::info;
use fnv::FnvHasher;
use memcrs_common::network::RequestHeader;
use memcrs_common::network::MAGIC_REQUEST;
use memcrs_common::network::OPCODE_GET;
use memcrs_common::{EbpfKey, EbpfValue};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

#[repr(C, packed)]
struct SockKey {
    remote_ip4: u32,
    local_ip4: u32,
    remote_port: u32,
    local_port: u32,
}

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
static SOCK_MAP: SockHash<SockKey> = SockHash::with_max_entries(1024, 0);

// #[xdp]
// pub fn xdp_packet_capture(ctx: XdpContext) -> u32 {
//     match try_xdp_packet_capture(ctx) {
//         Ok(ret) => ret,
//         Err(_) => xdp_action::XDP_ABORTED,
//     }
// }

// fn try_xdp_packet_capture(ctx: XdpContext) -> Result<u32, ()> {
//     let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
//     match unsafe { (*ethhdr).ether_type() } {
//         Ok(EtherType::Ipv4) => {}
//         _ => return Ok(xdp_action::XDP_PASS), // Ignore non-IPv4 packets
//     }

//     let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
//     let ipv4_header_len = (unsafe { (*ipv4hdr).ihl() } as usize);
//     let transport_header_offset = EthHdr::LEN + ipv4_header_len;

//     let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
//     let dest_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).dst_addr });

//     let (source_port, dest_port, payload_offset) = match unsafe { (*ipv4hdr).proto } {
//         IpProto::Tcp => {
//             let tcphdr: *const TcpHdr = ptr_at(&ctx, transport_header_offset)?;
//             let tcp_header_len = TcpHdr::LEN;

//             let payload_offset = transport_header_offset + tcp_header_len;
//             let source_port = u16::from_be_bytes(unsafe { (*tcphdr).source });
//             let dest_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });

//             (source_port, dest_port, payload_offset)
//         }
//         IpProto::Udp => {
//             let udphdr: *const UdpHdr = ptr_at(&ctx, transport_header_offset)?;
//             let udp_header_len = UdpHdr::LEN;

//             let payload_offset = transport_header_offset + udp_header_len;
//             let source_port = unsafe { (*udphdr).src_port() };
//             let dest_port = unsafe { (*udphdr).dst_port() };

//             // (source_port, dest_port, payload_offset)
//             return Ok(xdp_action::XDP_PASS); // Ignore UDP packets for now
//         }
//         _ => return Err(()),
//     };

//     let map_port_ref = CONFIG_PORT.get(0);
//     let memcached_port: u16 = match map_port_ref {
//         Some(port_value) => (*port_value) as u16,
//         None => 11211,
//     };

//     if dest_port != memcached_port {
//         return Ok(xdp_action::XDP_PASS); // Ignore packets not destined for memcached port
//     }

//     let payload_len = ctx.data_end() - (ctx.data() + payload_offset);
//     if payload_len < MEMCACHED_BIN_HEADER_LEN {
//         info!(
//             &ctx,
//             "XDP: Packet too short for memcached header: {} bytes", payload_len
//         );
//         return Ok(xdp_action::XDP_PASS); // Ignore packets that are too short to contain memcached header
//     }

//     let req_hdr: *const RequestHeader = ptr_at(&ctx, payload_offset)?;

//     let is_binary_request = unsafe { (*req_hdr).magic == MAGIC_REQUEST };
//     let is_get_command = unsafe { (*req_hdr).opcode == OPCODE_GET };

//     info!(
//         &ctx,
//         "XDP: Packet from {}:{} to {}:{} - Payload Length: {} bytes",
//         source_addr,
//         source_port,
//         dest_addr,
//         dest_port,
//         payload_len
//     );

//     if is_binary_request && is_get_command {
//         info!(
//             &ctx,
//             "XDP: Detected Binary TCP GET (Opcode: {}) on port {}", OPCODE_GET, dest_port
//         );
//     }

//     // hash the header fields to create the key
//     // hash_key(
//     //     &ctx,
//     //     0, // start from the beginning of the Ethernet header
//     //     payload_offset + CMD_LEN, // include up to the end of the command
//     // );

//     Ok(xdp_action::XDP_PASS)
// }

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

// --- SockOps Program for TCP Socket Management ---

#[sock_ops]
pub fn memcrs_sockops(ctx: SockOpsContext) -> u32 {
    match try_memcrs_sockops(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_memcrs_sockops(ctx: &SockOpsContext) -> Result<u32, ()> {
    let memcached_port: u32 = if let Some(port_value) = CONFIG_PORT.get(0) {
        *port_value
    } else {
        11211
    };

    let op = ctx.op();

    if ctx.local_port() != memcached_port {
        info!(
            &ctx,
            "SOCK_OPS: Ignoring non-memcached port socket: {}",
            ctx.local_port()
        );
        return Ok(0);
    }

    if op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB {
        let key: SockKey = SockKey {
            remote_ip4: ctx.remote_ip4(),
            local_ip4: ctx.local_ip4(),
            remote_port: ctx.remote_port(),
            local_port: ctx.local_port(),
        };

        let sk_ops = unsafe { &mut *(ctx.ops) };

        let result = SOCK_MAP.update(key, sk_ops, BPF_ANY.into()).ok();

        match result {
            Some(_) => {
                info!(
                    &ctx,
                    "SOCK_OPS: TCP socket established and added to SOCK_MAP"
                );
            }
            None => {
                info!(&ctx, "SOCK_OPS: Failed to add TCP socket");
            }
        }
    }

    Ok(0)
}

// --- SK_MSG Program for Memcached Request Handling ---

#[sk_msg]
pub fn memcrs_skmsg(ctx: SkMsgContext) -> u32 {
    match try_memcrs_skmsg(ctx) {
        Ok(ret) => ret,
        Err(_) => sk_action::SK_PASS,
    }
}

fn try_memcrs_skmsg(ctx: SkMsgContext) -> Result<u32, ()> {
    info!(&ctx, "SK_MSG: Received a message.");

    Ok(sk_action::SK_PASS)
}

//     // FIX: SkMsgContext does not expose 4-tuple IP/Port info directly.
//     // We use a constant key to reference the SockHash map for redirection,
//     // assuming the sock_ops program correctly links the socket to this key.
//     let flow_key = FALLBACK_FLOW_KEY;

//     // 1. Pre-check: Must have at least the 24-byte header
//     if msg_size < BINARY_HEADER_LEN {
//         return Ok(sk_action::SK_PASS);
//     }

//     // 2. Safely load the request header using read_unaligned
//     let req_hdr_ptr: *const RequestHeader = msg_ptr as *const RequestHeader;
//     let req_hdr: RequestHeader = unsafe { ptr::read_unaligned(req_hdr_ptr) };

//     // Not a binary request, pass up
//     if req_hdr.magic != MAGIC_REQUEST {
//         return Ok(sk_action::SK_PASS);
//     }

//     // Network byte order conversions
//     let key_len = u16::from_be(req_hdr.key_length) as usize;
//     let extras_len = req_hdr.extras_length as usize;
//     let body_len = u32::from_be(req_hdr.body_length) as usize;
//     let value_len = body_len.checked_sub(key_len + extras_len).unwrap_or(0);

//     let key_offset = BINARY_HEADER_LEN + extras_len;
//     let data_offset = key_offset + key_len;

//     // Validate request size
//     if body_len != key_len + extras_len + value_len || msg_size != BINARY_HEADER_LEN + body_len {
//         info!(&ctx, "SK_MSG: Invalid body length mismatch.");
//         return Ok(sk_action::SK_PASS);
//     }

//     // --- Centralized Logging for all Binary Requests ---
//     info!(
//         &ctx,
//         "SK_MSG: Binary Opcode 0x{:x} received. Key Len: {}, Body Len: {}",
//         req_hdr.opcode,
//         key_len,
//         body_len
//     );

//     match req_hdr.opcode {
//         // --- SET Command Handling (0x01) ---
//         OPCODE_SET => {
//             if key_len == 0 || key_len > BMC_MAX_KEY_LENGTH || extras_len != SET_EXTRAS_LEN {
//                 return Ok(sk_action::SK_PASS);
//             }

//             // Get Extras
//             let extras_ptr: *const SetExtras =
//                 unsafe { msg_ptr.offset(BINARY_HEADER_LEN as isize) as *const SetExtras };
//             let _extras: SetExtras = unsafe { ptr::read_unaligned(extras_ptr) };

//             // Hash the Key using the requested FnvHasher pattern
//             let key_hash = hash_key(&ctx, key_offset, key_len);
//             if key_hash == 0 {
//                 return Err(());
//             }

//             // Validate Data Block Length
//             if value_len == 0 || value_len > BMC_MAX_CACHE_DATA_SIZE {
//                 return Ok(sk_action::SK_PASS);
//             }

//             // Prepare and Insert into Cache Map
//             let mut new_entry = CacheEntryData {
//                 len: value_len as u32,
//                 valid: 1,
//                 hash: key_hash,
//                 data: [0u8; BMC_MAX_CACHE_DATA_SIZE],
//             };

//             // Copy data payload
//             unsafe {
//                 let src = msg_ptr.offset(data_offset as isize);
//                 core::ptr::copy_nonoverlapping(src, new_entry.data.as_mut_ptr(), value_len);
//             }

//             // Insert
//             if CACHE_MAP.insert(&key_hash, &new_entry, 0).is_ok() {
//                 info!(&ctx, "SK_MSG: SET Cache updated. Hash: {}", key_hash);

//                 // Inject Reply
//                 let reply_hdr = ResponseHeader {
//                     magic: MAGIC_RESPONSE,
//                     opcode: OPCODE_SET,
//                     status: STATUS_SUCCESS.to_be(),
//                     opaque: req_hdr.opaque,
//                     ..Default::default()
//                 };
//                 let reply_bytes = unsafe {
//                     core::slice::from_raw_parts(
//                         &reply_hdr as *const _ as *const u8,
//                         BINARY_HEADER_LEN,
//                     )
//                 };

//                 if inject_reply(&mut ctx, reply_bytes, flow_key).is_ok() {
//                     return Ok(sk_action::SK_PASS);
//                 } else {
//                     return Err(());
//                 }
//             } else {
//                 return Ok(sk_action::SK_PASS); // Fallback to userspace
//             }
//         }

//         // --- GET and Other Unhandled Commands ---
//         OPCODE_GET => {
//             // Logged above, now pass up to Memcached for execution
//             return Ok(sk_action::SK_PASS);
//         }

//         // Unhandled commands pass up
//         _ => {
//             return Ok(sk_action::SK_PASS);
//         }
//     }
// }

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
