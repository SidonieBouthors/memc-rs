#![no_std]

pub mod network;

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

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct SockKey {
    pub remote_ip4: u32,
    pub local_ip4: u32,
    pub remote_port: u32,
    pub local_port: u32,
}

// Required by Aya for use in eBPF maps
#[cfg(feature = "user")]
unsafe impl aya::Pod for EbpfValue {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SockKey {}
