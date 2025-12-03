use clap::ValueEnum;

pub mod dash_map_store;
pub mod moka_store;
pub mod ebpf_map_store;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum StoreEngine {
    /// store based on dashmap library
    DashMap,
    /// store based on moka library
    Moka,
    /// store based on eBPF maps
    EbpfMap,
}

impl StoreEngine {
    pub fn as_str(&self) -> &'static str {
        match self {
            StoreEngine::DashMap => "DashMap backend",
            StoreEngine::Moka => "Moka backend",
            StoreEngine::EbpfMap => "eBPF Map backend",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StoreEngine;

    #[test]
    fn test_as_str() {
        assert_eq!(StoreEngine::DashMap.as_str(), "DashMap backend");
        assert_eq!(StoreEngine::Moka.as_str(), "Moka backend");
        assert_eq!(StoreEngine::EbpfMap.as_str(), "eBPF Map backend");
    }

    #[test]
    fn test_enum_ordering() {
        assert!(StoreEngine::DashMap < StoreEngine::Moka);
        assert!(StoreEngine::Moka < StoreEngine::EbpfMap);
    }

    #[test]
    fn test_enum_equality() {
        assert_eq!(StoreEngine::DashMap, StoreEngine::DashMap);
        assert_eq!(StoreEngine::Moka, StoreEngine::Moka);
        assert_ne!(StoreEngine::DashMap, StoreEngine::Moka);
    }
}
