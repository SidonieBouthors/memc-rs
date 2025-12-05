pub const MAGIC_REQUEST: u8 = 0x80;
pub const MAGIC_RESPONSE: u8 = 0x81;

pub const OPCODE_GET: u8 = 0x00;
pub const OPCODE_SET: u8 = 0x01;

pub const STATUS_SUCCESS: u16 = 0x0000;
pub const STATUS_KEY_NOT_EXISTS: u16 = 0x0001;

pub const DATATYPE_RAW_BYTES: u8 = 0x00;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestHeader {
    pub magic: u8,
    pub opcode: u8,
    pub key_length: u16,      // Network byte order
    pub extras_length: u8,
    pub data_type: u8,
    pub vbucket_id: u16,      // Network byte order
    pub body_length: u32,     // Network byte order (Total body: key+extras+value)
    pub opaque: u32,          // Host byte order (opaque token)
    pub cas: u64,             // Host byte order (CAS token)
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ResponseHeader {
    pub magic: u8,
    pub opcode: u8,
    pub key_length: u16,      // Network byte order
    pub extras_length: u8,
    pub data_type: u8,
    pub status: u16,          // Network byte order
    pub body_length: u32,     // Network byte order
    pub opaque: u32,
    pub cas: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SetExtras {
    pub flags: u32,           // Host byte order
    pub expiration: u32,      // Host byte order
}