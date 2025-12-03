use crate::cache::cache::{
    impl_details, Cache, CacheMetaData, KeyType, Record, SetStatus, ValueType,
};
use crate::cache::error::{CacheError, Result};
use crate::server::timer;

use aya::maps::{HashMap, MapData};
use aya::Ebpf;
use fnv::FnvHasher;
use memcrs_common::{EbpfKey, EbpfValue, MAX_VALUE_SIZE};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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

fn ebpf_value_to_record(value: EbpfValue) -> Record {
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

type EbpfHashMap = HashMap<MapData, EbpfKey, EbpfValue>;
type Storage = Mutex<EbpfHashMap>;
pub struct EbpfMapMemoryStore {
    memory: Storage,
    timer: Arc<dyn timer::Timer + Send + Sync>,
    cas_id: AtomicU64,
    _ebpf: Ebpf,
}

impl EbpfMapMemoryStore {
    pub fn new(
        timer: Arc<dyn timer::Timer + Send + Sync>,
        ebpf: Ebpf,
        map_handle: EbpfHashMap,
    ) -> EbpfMapMemoryStore {
        EbpfMapMemoryStore {
            memory: Mutex::new(map_handle),
            timer,
            cas_id: AtomicU64::new(1),
            _ebpf: ebpf,
        }
    }

    fn get_cas_id(&self) -> u64 {
        self.cas_id.fetch_add(1, Ordering::Release)
    }

    fn set_cas_ttl(&self, mut record: Record, cas: u64) -> Record {
        record.header.cas = cas;
        let timestamp = self.timer.timestamp();
        if record.header.time_to_live != 0 {
            record.header.time_to_live += timestamp;
        }
        record
    }
}

impl impl_details::CacheImplDetails for EbpfMapMemoryStore {
    fn get_by_key(&self, key: &KeyType) -> Result<Record> {
        let ebpf_key = hash_key(key);
        let map = self.memory.lock().map_err(|_| CacheError::InternalError)?;
        match map.get(&ebpf_key, 0) {
            Ok(value) => {
                let record = ebpf_value_to_record(value);
                Ok(record)
            }
            Err(_) => Err(CacheError::NotFound),
        }
    }

    fn check_if_expired(&self, key: &KeyType, record: &Record) -> bool {
        let current_time = self.timer.timestamp();

        if record.header.time_to_live == 0 {
            return false;
        }

        if record.header.time_to_live > current_time {
            return false;
        }
        match self.remove(key) {
            Some(_) => true,
            None => true,
        }
    }
}

impl Cache for EbpfMapMemoryStore {
    fn remove(&self, key: &KeyType) -> Option<(KeyType, Record)> {
        let ebpf_key = hash_key(key);
        let mut map = match self.memory.lock() {
            Ok(guard) => guard,
            Err(_) => {
                eprintln!("Fatal: Mutex poisoned during remove operation.");
                return None;
            }
        };
        let value = match map.get(&ebpf_key, 0) {
            Ok(v) => v,
            Err(_) => return None,
        };
        match map.remove(&ebpf_key) {
            Ok(_) => {
                let record = ebpf_value_to_record(value);
                Some((key.clone(), record))
            }
            Err(_) => None,
        }
    }

    //Sets value that will be associated with a store. If value already exists in a store CAS field is compared and depending on CAS value comparison value is set or rejected.
    // if CAS is equal to 0 value is always set
    // if CAS is not equal value is not set and there is an error returned with status KeyExists
    fn set(&self, key: KeyType, record: Record) -> Result<SetStatus> {
        let ebpf_key = hash_key(&key);

        let mut map = self.memory.lock().map_err(|_| CacheError::InternalError)?;

        let new_cas = if record.header.cas > 0 {
            if let Ok(existing_value) = map.get(&ebpf_key, 0) {
                if existing_value.cas != record.header.cas {
                    return Err(CacheError::KeyExists);
                }
            }
            record.header.cas + 1
        } else {
            self.get_cas_id()
        };
        let updated_record = self.set_cas_ttl(record, new_cas);
        let updated_ebpf_value = record_to_ebpf_value(&updated_record)?;

        match map.insert(ebpf_key, updated_ebpf_value, 0) {
            Ok(_) => Ok(SetStatus { cas: new_cas }),
            Err(_) => Err(CacheError::InternalError),
        }
    }

    fn delete(&self, key: KeyType, header: CacheMetaData) -> Result<Record> {
        let ebpf_key = hash_key(&key);
        let mut map = self.memory.lock().map_err(|_| CacheError::InternalError)?;

        let value = map.get(&ebpf_key, 0).map_err(|_| CacheError::NotFound)?;

        if header.cas != 0 && value.cas != header.cas {
            return Err(CacheError::KeyExists);
        }

        map.remove(&ebpf_key)
            .map_err(|_| CacheError::InternalError)?;

        let record = ebpf_value_to_record(value);
        Ok(record)
    }

    fn flush(&self, header: CacheMetaData) {
        let mut map = match self.memory.lock() {
            Ok(guard) => guard,
            Err(e) => {
                eprintln!("Fatal: Mutex poisoned during flush() operation: {}", e);
                return;
            }
        };
        if header.time_to_live > 0 {
            let current_time = self.timer.timestamp();
            let flush_time = current_time + header.time_to_live;

            let keys_to_remove: Vec<EbpfKey> = map
                .iter()
                .filter_map(|res| {
                    if let Ok((key, value)) = res {
                        if value.time_to_live <= flush_time && value.time_to_live > 0 {
                            Some(key)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect();

            for key in keys_to_remove {
                let _ = map.remove(&key);
            }
        } else {
            let keys_to_remove: Vec<EbpfKey> = map.keys().filter_map(|res| res.ok()).collect();

            for key in keys_to_remove {
                let _ = map.remove(&key);
            }
        }
    }

    fn len(&self) -> usize {
        let map = match self.memory.lock() {
            Ok(guard) => guard,
            Err(e) => {
                eprintln!("Fatal: Mutex poisoned during len() operation: {}", e);
                return 0;
            }
        };
        map.iter().filter_map(|res| res.ok()).count()
    }

    fn run_pending_tasks(&self) {}
}
