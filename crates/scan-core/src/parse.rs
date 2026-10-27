//! Validates and parses a core WASM module with size and count caps.

use wasmparser::{Encoding, ExternalKind, Parser, Payload, TypeRef, Validator, WasmFeatures};

use crate::limits::{
    MAX_CUSTOM_SECTIONS, MAX_EXPORTS, MAX_IMPORTS, MAX_MODULE_BYTES, MAX_NAME_BYTES, MAX_PAYLOADS,
};
use crate::report::ScanError;

/// What the detectors need from a module. Custom-section contents are not
/// interpreted here: they are claims made by the module's author.
#[derive(Debug, Default)]
pub struct Module {
    /// Function imports as (module, name).
    pub function_imports: Vec<(String, String)>,
    pub function_exports: Vec<String>,
    pub custom_sections: Vec<String>,
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
                m.custom_sections.push(bounded(reader.name())?);
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
