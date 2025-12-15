#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::bindings::sk_action;
use aya_ebpf::bindings::BPF_ANY;
use aya_ebpf::bindings::BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB;
use aya_ebpf::bindings::BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB;
use aya_ebpf::macros::map;
use aya_ebpf::macros::sock_ops;
use aya_ebpf::macros::stream_parser;
use aya_ebpf::macros::stream_verdict;
use aya_ebpf::maps::SockHash;
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::programs::SkBuffContext;
use aya_ebpf::programs::SockOpsContext;
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::info;
use memcrs_common::network::RequestHeader;
use memcrs_common::SockKey;
use memcrs_common::{EbpfKey, EbpfValue};

const MEMCACHED_BIN_HEADER_LEN: usize = core::mem::size_of::<RequestHeader>();

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

#[map]
static SOCK_MAP: SockHash<SockKey> = SockHash::with_max_entries(1024, 0);

// --- SockOps Program for TCP Socket Management ---

#[sock_ops]
pub fn memcrs_sockops(ctx: SockOpsContext) -> u32 {
    try_memcrs_sockops(&ctx).unwrap_or_default()
}

/// Manages TCP sockets for memcached communication.
/// Adds established TCP sockets to the SOCK_MAP for later use
/// (the stream parser program will be called on messages received by these sockets)
fn try_memcrs_sockops(ctx: &SockOpsContext) -> Result<u32, ()> {
    let memcached_port: u32 = if let Some(port_value) = CONFIG_PORT.get(0) {
        *port_value
    } else {
        11211
    };

    let op = ctx.op();

    if ctx.remote_port() != memcached_port && ctx.local_port() != memcached_port {
        // Not a message for memcached port, ignore
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

#[stream_parser]
pub fn memcrs_parser(ctx: SkBuffContext) -> u32 {
    try_memcrs_parser(ctx).unwrap_or_default()
}

/// This functions is meant to parse incoming memcached messages via TCP
/// However, the return values do not act as described in the documentation
/// https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SK_SKB/
/// This seems to be an Aya limitation / bug, which means that we cannot
/// pass control to userspace correctly or otherwise handle the messages
/// as intended.
/// https://github.com/aya-rs/aya/issues/1411
fn try_memcrs_parser(ctx: SkBuffContext) -> Result<u32, ()> {
    info!(&ctx, "SKB: Received a message.");

    // Print ip and ports
    let remote_ip4 = ctx.skb.remote_ipv4();
    let local_ip4 = ctx.skb.local_ipv4();
    let remote_port = ctx.skb.remote_port();
    let local_port = ctx.skb.local_port();

    info!(
        &ctx,
        "SKB: Message details - remote_ip4: {}, local_ip4: {}, remote_port: {}, local_port: {}",
        remote_ip4,
        local_ip4,
        remote_port,
        local_port
    );

    if ctx.len() < MEMCACHED_BIN_HEADER_LEN as u32 {
        info!(
            &ctx,
            "SKB: Message too short for memcached header ({} bytes).",
            ctx.len()
        );

        return Ok(ctx.len());
    }

    let header: RequestHeader = match ctx.load(0) {
        Ok(h) => h,
        Err(_) => {
            info!(&ctx, "Failed to load Memcached header.");
            return Err(()); // Pass control to userspace
        }
    };

    // log the opcode
    info!(&ctx, "SKB: Memcached Request Magic: {}", header.magic);

    Ok(ctx.len())
}

/// Stream verdict program must be present in order to use stream parser
/// but we don't need it to do anything special so we just pass the packet
#[stream_verdict]
pub fn memcrs_verdict(ctx: SkBuffContext) -> u32 {
    sk_action::SK_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
