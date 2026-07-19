//! SPDX SBOM generation at pack time.

use std::path::Path;

use crate::cmd::fmt::core::manifest::ZexTomlManifest;
use crate::cmd::fmt::error::Result;

#[derive(serde::Serialize)]
struct SpdxDocument {
    #[serde(rename = "spdxVersion")]
    spdx_version: &'static str,
    #[serde(rename = "dataLicense")]
    data_license: &'static str,
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(rename = "documentNamespace")]
    document_namespace: String,
    packages: Vec<SpdxPackage>,
    files: Vec<SpdxFile>,
    relationships: Vec<SpdxRelationship>,
}

#[derive(serde::Serialize)]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    version: String,
    #[serde(rename = "downloadLocation")]
    download_location: String,
    #[serde(rename = "licenseDeclared")]
    license_declared: String,
    #[serde(rename = "copyrightText")]
    copyright_text: String,
}

#[derive(serde::Serialize)]
struct SpdxFile {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    #[serde(rename = "fileName")]
    file_name: String,
    #[serde(rename = "checksums")]
    checksums: Vec<SpdxChecksum>,
}

#[derive(serde::Serialize)]
struct SpdxChecksum {
    #[serde(rename = "algorithm")]
    algorithm: &'static str,
    #[serde(rename = "checksumValue")]
    checksum_value: String,
}

#[derive(serde::Serialize)]
struct SpdxRelationship {
    #[serde(rename = "spdxElementId")]
    spdx_element_id: String,
    #[serde(rename = "relatedSpdxElement")]
    related_spdx_element: String,
    #[serde(rename = "relationshipType")]
    relationship_type: &'static str,
}

/// Generate an SPDX 2.3 JSON SBOM for a packed `.zex` payload.
pub fn generate_spdx(
    source_dir: &Path,
    manifest: &ZexTomlManifest,
    payload_files: &[(String, Vec<u8>)],
) -> Result<String> {
    let name = &manifest.package.name;
    let version = &manifest.package.version;
    let ns = format!("https://archive.zainiumdynamics.tech/spdx/{name}-{version}");

    let mut files = Vec::new();
    let mut relationships = Vec::new();

    for (i, (rel, bytes)) in payload_files.iter().enumerate() {
        let fid = format!("SPDXRef-File-{i}");
        let hash = blake3::hash(bytes).to_hex().to_string();
        files.push(SpdxFile {
            spdx_id: fid.clone(),
            file_name: rel.clone(),
            checksums: vec![SpdxChecksum {
                algorithm: "BLAKE3",
                checksum_value: hash,
            }],
        });
        relationships.push(SpdxRelationship {
            spdx_element_id: "SPDXRef-Package".into(),
            related_spdx_element: fid,
            relationship_type: "CONTAINS",
        });
    }

    let doc = SpdxDocument {
        spdx_version: "SPDX-2.3",
        data_license: "CC0-1.0",
        spdx_id: "SPDXRef-DOCUMENT".into(),
        name: format!("{name}-{version}"),
        document_namespace: ns,
        packages: vec![SpdxPackage {
            spdx_id: "SPDXRef-Package".into(),
            name: name.clone(),
            version: version.clone(),
            download_location: "NOASSERTION".into(),
            license_declared: manifest.package.license.clone(),
            copyright_text: format!("NOASSERTION (built from {})", source_dir.display()),
        }],
        files,
        relationships,
    };

    serde_json::to_string_pretty(&doc).map_err(|e| {
        crate::cmd::fmt::error::ZexError::Other(format!("SBOM serialize error: {e}"))
    })
}