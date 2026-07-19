use crate::cmd::fmt::core::scanner::{ManifestIntegrityResult, PermissionAuditResult};
use crate::cmd::fmt::security::c_audit::CAuditReport;
use crate::cmd::fmt::security::root_guard::{ContentScanResult, LayoutCheckResult};
use crate::cmd::fmt::security::rust_audit::RustAuditReport;
use crate::cmd::fmt::security::secrets_scan::SecretsScanReport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityReport {
    pub schema: String,
    pub layout_check: LayoutCheckResult,
    pub content_scan: ContentScanResult,
    pub manifest_integrity: ManifestIntegrityResult,
    pub permission_audit: PermissionAuditResult,
    /// Not applicable for non-Rust packages.
    pub rust_audit: RustAuditReport,
    /// Not applicable for packages with no C/C++ sources.
    pub c_audit: CAuditReport,
    /// Always runs — blocks pack if any secrets found.
    pub secrets_scan: SecretsScanReport,
}

impl SecurityReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        layout_check: LayoutCheckResult,
        content_scan: ContentScanResult,
        manifest_integrity: ManifestIntegrityResult,
        permission_audit: PermissionAuditResult,
        rust_audit: RustAuditReport,
        c_audit: CAuditReport,
        secrets_scan: SecretsScanReport,
    ) -> Self {
        SecurityReport {
            schema: "zainium-security-report-v2".to_string(),
            layout_check,
            content_scan,
            manifest_integrity,
            permission_audit,
            rust_audit,
            c_audit,
            secrets_scan,
        }
    }

    pub fn to_json_pretty(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}
