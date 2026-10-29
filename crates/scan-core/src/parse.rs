//! Validates and parses a core WASM module with size and count caps.

use wasmparser::{Encoding, ExternalKind, Parser, Payload, TypeRef, Validator, WasmFeatures};

use crate::limits::{
    MAX_CUSTOM_SECTIONS, MAX_ENV_META_BYTES, MAX_ENV_META_SECTIONS, MAX_EXPORTS, MAX_IMPORTS,
    MAX_MODULE_BYTES, MAX_NAME_BYTES, MAX_PAYLOADS, MAX_SPEC_BYTES, MAX_SPEC_SECTIONS,
};
use crate::meta::ENV_META_SECTION;
use crate::report::ScanError;
use crate::spec::SPEC_SECTION;

/// What the detectors need from a module. Custom-section contents are claims
/// made by the module's author and are not interpreted here; the bytes of one
/// section are retained for `crate::meta` and `crate::spec` to read.
#[derive(Debug, Default)]
pub struct Module {
    /// Function imports as (module, name).
    pub function_imports: Vec<(String, String)>,
    pub function_exports: Vec<String>,
    pub custom_sections: Vec<String>,
    /// Each `contractenvmetav0` body seen, in order, capped in count and size.
    /// An oversized body is kept as empty so it can never look like one
    /// readable claim.
    pub env_meta_bodies: Vec<Vec<u8>>,
    /// Each `contractspecv0` body seen, under the same rule: oversized is
    /// kept as empty, because an unreadable spec must not read as no functions.
    pub spec_bodies: Vec<Vec<u8>>,
}

impl Module {
    pub fn imports(&self, module: &str, name: &str) -> bool {
        self.function_imports
            .iter()
            .any(|(m, n)| m == module && n == name)
    }

    pub fn has_custom_section(&self, name: &str) -> bool {
        self.custom_sections.iter().any(|s| s == name)
    }
}

pub fn parse(bytes: &[u8]) -> Result<Module, ScanError> {
    if bytes.len() > MAX_MODULE_BYTES {
        return Err(ScanError::TooLarge);
    }
    // TODO(verify): Soroban's exact enabled feature set; default features are a superset.
    Validator::new_with_features(WasmFeatures::default())
        .validate_all(bytes)
        .map_err(|_| ScanError::Invalid)?;

    let mut m = Module::default();
    for (i, payload) in Parser::new(0).parse_all(bytes).enumerate() {
        if i >= MAX_PAYLOADS {
            return Err(ScanError::LimitExceeded("sections"));
        }
        match payload.map_err(|_| ScanError::Invalid)? {
            Payload::Version { encoding, .. } => {
                if encoding != Encoding::Module {
                    return Err(ScanError::NotCoreModule);
                }
            }
            Payload::ImportSection(reader) => {
                // into_imports flattens the compact encodings, so no import is skipped.
                for import in reader.into_imports() {
                    let import = import.map_err(|_| ScanError::Invalid)?;
                    if matches!(import.ty, TypeRef::Func(_) | TypeRef::FuncExact(_)) {
                        if m.function_imports.len() >= MAX_IMPORTS {
                            return Err(ScanError::LimitExceeded("imports"));
                        }
                        m.function_imports
                            .push((bounded(import.module)?, bounded(import.name)?));
                    }
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|_| ScanError::Invalid)?;
                    if export.kind == ExternalKind::Func {
                        if m.function_exports.len() >= MAX_EXPORTS {
                            return Err(ScanError::LimitExceeded("exports"));
                        }
                        m.function_exports.push(bounded(export.name)?);
                    }
                }
            }
            Payload::CustomSection(reader) => {
                if m.custom_sections.len() >= MAX_CUSTOM_SECTIONS {
                    return Err(ScanError::LimitExceeded("custom_sections"));
                }
                let name = bounded(reader.name())?;
                if name == ENV_META_SECTION {
                    let data = reader.data();
                    let retain = data.len() <= MAX_ENV_META_BYTES
                        && m.env_meta_bodies.len() < MAX_ENV_META_SECTIONS;
                    m.env_meta_bodies
                        .push(if retain { data.to_vec() } else { Vec::new() });
                }
                if name == SPEC_SECTION {
                    let data = reader.data();
                    let retain =
                        data.len() <= MAX_SPEC_BYTES && m.spec_bodies.len() < MAX_SPEC_SECTIONS;
                    m.spec_bodies
                        .push(if retain { data.to_vec() } else { Vec::new() });
                }
                m.custom_sections.push(name);
            }
            _ => {}
        }
    }
    Ok(m)
}

fn bounded(s: &str) -> Result<String, ScanError> {
    if s.len() > MAX_NAME_BYTES {
        return Err(ScanError::LimitExceeded("name_length"));
    }
    Ok(s.to_owned())
}
