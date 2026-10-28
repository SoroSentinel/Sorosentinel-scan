//! The `contractenvmetav0` custom section: an `SCEnvMetaEntry` written by the
//! contract's author. The network does not check it, so it is a claim.
//!
//! Shape verified against two primary sources, not assumed:
//! - `go-stellar-sdk` v0.7.3 `xdr.ScEnvMetaEntry`: a union on `kind` (int32,
//!   only arm 0 = interface version) carrying `{ uint32 protocol; uint32
//!   preRelease }`, so 12 bytes big-endian in total.
//! - 73 distinct contract modules deployed on testnet, read from ledger
//!   metadata on 2026-10-28: every one is exactly 12 bytes with kind 0, and
//!   `protocol` ranges 21..=29.

pub const ENV_META_SECTION: &str = "contractenvmetav0";

/// The only `SCEnvMetaKind` arm in the pinned XDR.
const INTERFACE_VERSION_KIND: u32 = 0;
/// 4 bytes of union discriminant plus two `uint32`s.
const ENTRY_BYTES: usize = 12;

/// A protocol version claimed by the module itself. `pre_release` is the
/// XDR's second field: non-zero means a pre-release build of that protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvMetaClaim {
    pub protocol: u32,
    pub pre_release: u32,
}

/// Reads one claim from one section body. Anything that is not exactly one
/// well-formed interface-version entry — absent, truncated, oversized, trailing
/// bytes, an unknown union arm — is `None`: an unreadable claim is reported as
/// no claim, never guessed into a value.
pub fn parse(body: Option<&[u8]>) -> Option<EnvMetaClaim> {
    let body = body?;
    if body.len() != ENTRY_BYTES {
        return None;
    }
    let mut fixed = [0u8; ENTRY_BYTES];
    fixed.copy_from_slice(body);
    let kind = u32::from_be_bytes(fixed[0..4].try_into().ok()?);
    if kind != INTERFACE_VERSION_KIND {
        return None;
    }
    Some(EnvMetaClaim {
        protocol: u32::from_be_bytes(fixed[4..8].try_into().ok()?),
        pre_release: u32::from_be_bytes(fixed[8..12].try_into().ok()?),
    })
}

/// The bytes a claim would be read from, or `None` when the module made more
/// than one: two `contractenvmetav0` sections assert different protocols, and
/// picking one would be a guess.
pub fn sole_body(bodies: &[Vec<u8>]) -> Option<&[u8]> {
    match bodies {
        [one] => Some(one),
        _ => None,
    }
}

/// The one claim a module makes, if it makes exactly one that can be read.
pub fn claim(bodies: &[Vec<u8>]) -> Option<EnvMetaClaim> {
    parse(sole_body(bodies))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: u32, protocol: u32, pre_release: u32) -> Vec<u8> {
        [kind, protocol, pre_release]
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect()
    }

    #[test]
    fn reads_the_shape_real_modules_carry() {
        // The observed 12-byte body from a deployed testnet module.
        let body = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            parse(Some(&body)),
            Some(EnvMetaClaim {
                protocol: 23,
                pre_release: 0
            })
        );
    }

    #[test]
    fn absent_is_absent() {
        assert_eq!(parse(None), None);
    }

    #[test]
    fn every_malformed_form_is_no_claim() {
        for body in [
            vec![],
            entry(0, 23, 0)[..11].to_vec(), // truncated
            entry(0, 23, 0)[..8].to_vec(),
            [entry(0, 23, 0), vec![0xff]].concat(), // trailing byte
            vec![0xff; 12],                         // unknown arm, garbage
            entry(1, 23, 0),                        // unknown union arm
            entry(0, 23, 0).into_iter().cycle().take(4096).collect(), // oversized
        ] {
            assert_eq!(parse(Some(&body)), None, "len {}", body.len());
        }
    }

    #[test]
    fn an_explicit_zero_is_a_claim_not_an_absence() {
        // Well-formed but almost certainly false: it is still what the module
        // says, so it is surfaced as a claim rather than dropped.
        assert_eq!(
            parse(Some(&entry(0, 0, 0))),
            Some(EnvMetaClaim {
                protocol: 0,
                pre_release: 0
            })
        );
    }

    #[test]
    fn duplicated_sections_are_not_trusted() {
        assert!(sole_body(&[]).is_none());
        assert!(sole_body(&[entry(0, 23, 0), entry(0, 29, 0)]).is_none());
        assert_eq!(sole_body(&[entry(0, 23, 0)]).map(|b| b.len()), Some(12));
        // Parse keeps an empty body for an oversized or extra section, so a
        // module that shouts never produces a claim.
        assert_eq!(claim(&[Vec::new()]), None);
        assert_eq!(claim(&[entry(0, 23, 0), Vec::new()]), None);
        assert_eq!(
            claim(&[entry(0, 22, 0)]),
            Some(EnvMetaClaim {
                protocol: 22,
                pre_release: 0
            })
        );
    }
}
