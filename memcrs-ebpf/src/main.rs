#![no_std]
#![no_main]

use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use memcrs_common::{EbpfKey, EbpfValue};

static MAX_ENTRIES: u32 = 1024 * 1024;

#[map]
static CACHE_MAP: HashMap<EbpfKey, EbpfValue> = HashMap::with_max_entries(
    MAX_ENTRIES,
    0, // flags
);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
