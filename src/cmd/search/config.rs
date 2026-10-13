//! config.rs — Loads zex_services.toml for search mirror routing.

use serde::Deserialize;

const ZEX_SERVICES: &str = "/overlayer/syshub/engine/services/zex_services.toml";

#[derive(Debug, Deserialize)]
pub struct ZexServices {
    #[serde(default)]
    pub mirrors: Vec<Mirror>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Mirror {
    pub id: String,
    pub base_url: String,
    pub index_url: String,
    pub format: String,
    pub priority: u32,
    #[serde(default)]
    pub supported_archs: Vec<String>,
}

impl ZexServices {
    pub fn load() -> Self {
        let paths = [ZEX_SERVICES, "zex_services.toml"];
        for path in paths {
            if let Ok(raw) = std::fs::read_to_string(path) {
                if let Ok(svc) = toml::from_str::<Self>(&raw) {
                    return svc;
                }
            }
        }
        Self {
            mirrors: Vec::new(),
        }
    }

    pub fn mirror_by_id(&self, id: &str) -> Option<&Mirror> {
        self.mirrors.iter().find(|m| m.id == id)
    }

    pub fn mirrors_by_format(&self, fmt: &str) -> Vec<&Mirror> {
        let mut ms: Vec<&Mirror> = self.mirrors.iter().filter(|m| m.format == fmt).collect();
        ms.sort_by_key(|m| m.priority);
        ms
    }
}
