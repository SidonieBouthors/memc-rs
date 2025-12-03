use crate::cache::cache::{
    impl_details, Cache, CacheMetaData, KeyType, Record, SetStatus, ValueType,
};
use crate::cache::error::{CacheError, Result};
use crate::server::timer;

use aya::maps::{HashMap, MapData};
use fnv::FnvHasher;
use memcrs_common::{EbpfKey, EbpfValue, MAX_VALUE_SIZE};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn hash_key(key: &KeyType) -> EbpfKey {
    // Treat the Bytes object as a slice of bytes
    let data_slice: &[u8] = key.as_ref();

    let mut hasher = FnvHasher::default();
    data_slice.hash(&mut hasher);
    hasher.finish()
}

fn record_to_ebpf_value(record: &Record) -> Result<EbpfValue> {
    // Treat the Bytes object as a slice of bytes
    let data_slice: &[u8] = record.value.as_ref();

    if data_slice.len() > MAX_VALUE_SIZE {
        return Err(CacheError::ValueTooLarge);
    }

    let mut ebpf_value = EbpfValue {
        cas: record.header.cas,
        flags: record.header.flags,
        time_to_live: record.header.time_to_live,
        data_len: data_slice.len() as u32,
        _padding: 0,
        data: [0u8; MAX_VALUE_SIZE],
    };

    // Copy the contents of the Bytes object into the fixed-size array
    ebpf_value.data[..data_slice.len()].copy_from_slice(data_slice);

    Ok(ebpf_value)
}

fn ebpf_value_to_record(key: KeyType, value: EbpfValue) -> Record {
    let data_len = value.data_len as usize;

    // Extract the slice of the actual data
    let data_slice = &value.data[..data_len];

    // Convert the slice back into the high-level Bytes type
    let value_type = ValueType::from(data_slice.to_vec());

    Record {
        header: CacheMetaData {
            cas: value.cas,
            flags: value.flags,
            time_to_live: value.time_to_live,
        },
        value: value_type,
    }
}

// Cache error From impls for eBPF map operations
impl From<aya::maps::MapError> for CacheError {
    fn from(err: aya::maps::MapError) -> CacheError {
        match err {
            aya::maps::MapError::KeyNotFound => CacheError::NotFound,
            _ => CacheError::InternalError,
        }
    }
}

impl From<aya::EbpfError> for CacheError {
    fn from(_err: aya::EbpfError) -> CacheError {
        CacheError::InternalError
    }
}

type Storage = HashMap<MapData, EbpfKey, EbpfValue>;
pub struct EbpfMapMemoryStore {
    memory: Storage,
    timer: Arc<dyn timer::Timer + Send + Sync>,
    cas_id: AtomicU64,
}

impl EbpfMapMemoryStore {
    pub fn new(
        timer: Arc<dyn timer::Timer + Send + Sync>,
        map_handle: Storage,
    ) -> EbpfMapMemoryStore {
        EbpfMapMemoryStore {
            memory: map_handle,
            timer,
            cas_id: AtomicU64::new(1),
        }
    }
}

impl impl_details::CacheImplDetails for EbpfMapMemoryStore {
    fn get_by_key(&self, key: &KeyType) -> Result<Record> {
        let key_hash = hash_key(key);
        match self.memory.get(&key_hash, 0) {
            Ok(value) => {
                let record = ebpf_value_to_record(key.clone(), value);
                Ok(record)
            }
            Err(_) => Err(CacheError::NotFound),
        }
    }

    fn check_if_expired(&self, key: &KeyType, record: &Record) -> bool {
        todo!()
    }
}

impl Cache for EbpfMapMemoryStore {
    // Removes key value and returns as an option
    fn remove(&self, key: &KeyType) -> Option<(KeyType, Record)> {
        // self.memory.remove(key)
        todo!()
    }

    fn set(&self, key: KeyType, record: Record) -> Result<SetStatus> {
        todo!()
    }

    fn delete(&self, key: KeyType, header: CacheMetaData) -> Result<Record> {
        todo!()
    }

    fn flush(&self, header: CacheMetaData) {
        todo!()
    }

    fn len(&self) -> usize {
        todo!()
    }

    fn run_pending_tasks(&self) {
        todo!()
    }
}
