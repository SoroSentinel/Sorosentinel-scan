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
/// Retained size of one `contractspecv0` body. Measured 2026-10-29 across the
/// 61 distinct contract modules deployed in 6000 testnet ledgers: the largest
/// body was 28,056 bytes. This leaves room for a full token spec and stays
/// well under `MAX_MODULE_BYTES`, so a section can never be retained unbounded.
pub const MAX_SPEC_BYTES: usize = 64 << 10;
/// `SCSpecEntry` values read from one body; the same sample peaked at 117.
pub const MAX_SPEC_ENTRIES: u32 = 512;
/// `SCSpecTypeDef` nesting depth. The same sample peaked at 3; beyond this the
/// body is not followed at all rather than guessed at.
pub const MAX_SPEC_DEPTH: u32 = 8;
/// Strings read from one body, so a nesting-free but endless sequence of empty
/// arrays cannot make the reader run.
pub const MAX_SPEC_STRINGS: u32 = 20_000;
/// A spec is only read when exactly this many sections carry it, as with
/// `MAX_ENV_META_SECTIONS`: two sections claiming different signatures cancel
/// out instead of one being picked.
pub const MAX_SPEC_SECTIONS: usize = 2;
