#![no_std]

pub type EbpfKey = u64;

pub const MAX_VALUE_SIZE: usize = 5120;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct EbpfValue {
    // Metadata (From CacheMetaData)
    pub cas: u64,
    pub flags: u32,
    pub time_to_live: u32,

    // Data Length
    pub data_len: u32, // Actual length of the data stored in the array
    pub _padding: u32, // Ensures 8-byte alignment for the data array

    // Fixed-Size Data Buffer
    pub data: [u8; MAX_VALUE_SIZE],
}

// Required by Aya for use in eBPF maps
#[cfg(feature = "user")]
unsafe impl aya::Pod for EbpfValue {}
