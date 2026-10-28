//! Resource caps for hostile input. These are our own safety limits, not
//! network rules: TODO(verify) the network's maximum contract size and set
//! MAX_MODULE_BYTES no lower than it.

pub const MAX_MODULE_BYTES: usize = 1 << 20;
pub const MAX_PAYLOADS: usize = 256;
pub const MAX_CUSTOM_SECTIONS: usize = 32;
pub const MAX_IMPORTS: usize = 4096;
pub const MAX_EXPORTS: usize = 4096;
pub const MAX_NAME_BYTES: usize = 256;
pub const MAX_KNOWN_BAD_HASHES: usize = 1_000_000;
/// One `SCEnvMetaEntry` is 12 bytes; this leaves room for the arm and a
/// version. Anything larger is a hostile blob and is not retained at all.
pub const MAX_ENV_META_BYTES: usize = 128;
/// A claim is only read when exactly this many sections carry it.
pub const MAX_ENV_META_SECTIONS: usize = 2;
