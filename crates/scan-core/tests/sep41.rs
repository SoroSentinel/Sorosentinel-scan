//! `S-SEP41-DEVIATION`: the contractspecv0 reader and the SEP-41 comparison.
//! Sections are assembled byte by byte as XDR, so every arm of `SCSpecEntry`
//! and `SCSpecTypeDef` is walked deliberately rather than by accident.

mod common;

use common::module;
use scan_core::{KnownBadHashes, ScanReport, scan};

const SPEC: &str = "contractspecv0";

fn u32_bytes(n: u32, out: &mut Vec<u8>) {
    out.extend(n.to_be_bytes());
}

/// XDR `string<max>`: length, bytes, zero padding to a 4-byte boundary.
fn xdr_string(s: &str, out: &mut Vec<u8>) {
    u32_bytes(s.len() as u32, out);
    out.extend(s.as_bytes());
    let pad = (4 - s.len() % 4) % 4;
    out.extend(std::iter::repeat_n(0u8, pad));
}

/// A `SCSpecTypeDef` with no payload, e.g. `Address` (19) or `I128` (11).
fn plain(tag: u32, out: &mut Vec<u8>) {
    u32_bytes(tag, out);
}

fn vec_of(inner: &[u8], out: &mut Vec<u8>) {
    u32_bytes(1002, out);
    out.extend(inner);
}

/// One `SCSpecFunctionV0` entry: doc, name, inputs, output if any.
fn function(sig: &str, inputs: &[&[u8]], output: Option<&[u8]>) -> Vec<u8> {
    let (name, _) = sig.split_once('(').unwrap_or((sig, ""));
    let mut b = Vec::new();
    xdr_string("", &mut b); // doc
    xdr_string(name, &mut b); // name: SCSymbol, string<32>
    u32_bytes(inputs.len() as u32, &mut b);
    for input in inputs {
        xdr_string("", &mut b); // parameter doc
        xdr_string("a", &mut b); // parameter name
        b.extend(*input);
    }
    match output {
        Some(o) => {
            u32_bytes(1, &mut b);
            b.extend(o);
        }
        None => u32_bytes(0, &mut b),
    }
    let mut out = Vec::new();
    u32_bytes(0, &mut out); // SC_SPEC_ENTRY_FUNCTION_V0
    out.extend(b);
    out
}

/// The ten `TokenInterface` functions exactly as SEP-41 v0.5.2 and the SDK's
/// `token::TokenInterface` both state them.
fn conforming_token() -> Vec<u8> {
    let address = {
        let mut v = Vec::new();
        plain(19, &mut v);
        v
    };
    let muxed = {
        let mut v = Vec::new();
        plain(20, &mut v);
        v
    };
    let i128 = {
        let mut v = Vec::new();
        plain(11, &mut v);
        v
    };
    let u32_ = {
        let mut v = Vec::new();
        plain(4, &mut v);
        v
    };
    let string_ = {
        let mut v = Vec::new();
        plain(16, &mut v);
        v
    };
    let mut out = Vec::new();
    out.extend(function("allowance", &[&address, &address], Some(&i128)));
    out.extend(function(
        "approve",
        &[&address, &address, &i128, &u32_],
        None,
    ));
    out.extend(function("balance", &[&address], Some(&i128)));
    out.extend(function("transfer", &[&address, &muxed, &i128], None));
    out.extend(function(
        "transfer_from",
        &[&address, &address, &address, &i128],
        None,
    ));
    out.extend(function("burn", &[&address, &i128], None));
    out.extend(function("burn_from", &[&address, &address, &i128], None));
    out.extend(function("decimals", &[], Some(&u32_)));
    out.extend(function("name", &[], Some(&string_)));
    out.extend(function("symbol", &[], Some(&string_)));
    out
}

fn report_of(spec: &[u8]) -> ScanReport {
    scan(
        &module(&[], &[], &[(SPEC, spec)]),
        &KnownBadHashes::default(),
    )
    .unwrap()
}

fn deviation(r: &ScanReport) -> Option<&scan_core::Indicator> {
    r.indicators.iter().find(|i| i.code == "S-SEP41-DEVIATION")
}

#[test]
fn a_conforming_token_claim_raises_nothing() {
    let r = report_of(&conforming_token());
    assert!(r.claimed_meta.spec_present);
    assert!(
        deviation(&r).is_none(),
        "indicators: {:?}",
        r.indicators.iter().map(|i| i.code).collect::<Vec<_>>()
    );
}

#[test]
fn a_transfer_that_takes_a_plain_address_is_reported_as_a_deviation() {
    // The shape measured in a real testnet module on 2026-10-29: nine of the
    // ten interface functions match and `transfer` declares `to: Address`, so
    // the module cannot take a muxed destination.
    let mut spec = Vec::new();
    let mut address = Vec::new();
    plain(19, &mut address);
    let mut i128 = Vec::new();
    plain(11, &mut i128);
    let mut string_ = Vec::new();
    plain(16, &mut string_);
    spec.extend(function("transfer", &[&address, &address, &i128], None));
    spec.extend(function("balance", &[&address], Some(&i128)));
    spec.extend(function("symbol", &[], Some(&string_)));

    let r = report_of(&spec);
    let d = deviation(&r).expect("deviation reported");
    assert!(d.informational, "must never raise a level alone");
    assert_eq!(d.facts["deviating_function_count"], "1");
    assert_eq!(d.facts["missing_function_count"], "7");
    assert_eq!(d.facts["declared_interface_functions"], "3");
    let text = &d.facts["deviating_functions"];
    assert_eq!(
        text,
        "transfer: expected fn(Address, MuxedAddress, I128) -> void, reads fn(Address, Address, I128) -> void"
    );
    assert_eq!(
        d.facts["missing_functions"],
        "allowance,approve,burn,burn_from,decimals,name,transfer_from"
    );
}

#[test]
fn a_missing_interface_function_is_named() {
    // Six of the ten interface names, all conforming: the four absent ones are
    // the observation.
    let mut spec = Vec::new();
    let address = {
        let mut v = Vec::new();
        plain(19, &mut v);
        v
    };
    let i128 = {
        let mut v = Vec::new();
        plain(11, &mut v);
        v
    };
    let u32_ = {
        let mut v = Vec::new();
        plain(4, &mut v);
        v
    };
    let string_ = {
        let mut v = Vec::new();
        plain(16, &mut v);
        v
    };
    let muxed = {
        let mut v = Vec::new();
        plain(20, &mut v);
        v
    };
    spec.extend(function("allowance", &[&address, &address], Some(&i128)));
    spec.extend(function("balance", &[&address], Some(&i128)));
    spec.extend(function("transfer", &[&address, &muxed, &i128], None));
    spec.extend(function("decimals", &[], Some(&u32_)));
    spec.extend(function("name", &[], Some(&string_)));
    spec.extend(function("symbol", &[], Some(&string_)));

    let r = report_of(&spec);
    let d = deviation(&r).expect("deviation reported");
    assert_eq!(d.facts["declared_interface_functions"], "6");
    assert_eq!(d.facts["deviating_function_count"], "0");
    assert_eq!(
        d.facts["missing_functions"],
        "approve,burn,burn_from,transfer_from"
    );
    assert_eq!(d.facts["missing_function_count"], "4");
    // The baseline itself is reported, so the observation is checkable.
    assert!(d.facts["required_function_names"].contains("approve"));
}

#[test]
fn a_module_that_does_not_read_as_a_token_is_not_compared() {
    // Two interface names only. `name` and `symbol` are ordinary function
    // names elsewhere, so the claim needs the measured floor to trigger.
    let address = {
        let mut v = Vec::new();
        plain(19, &mut v);
        v
    };
    let mut spec = Vec::new();
    spec.extend(function("name", &[], Some(&address)));
    spec.extend(function("symbol", &[], None));
    spec.extend(function("withdraw", &[&address], None));
    let r = report_of(&spec);
    assert!(deviation(&r).is_none(), "2 of 10 names must not trigger");
}

#[test]
fn nested_type_arms_are_walked_and_rendered() {
    // `allowance(Address, Vec<Map<String, Option<Udt:Bal>>>) -> Result<I128,
    // Tuple<U32, BytesN<32>>)`: every parameterised arm in one signature, all
    // of which deviate from the interface.
    let mut inner = Vec::new();
    {
        let mut udt = Vec::new();
        u32_bytes(2000, &mut udt);
        xdr_string("Bal", &mut udt);
        let mut opt = Vec::new();
        u32_bytes(1000, &mut opt);
        opt.extend(udt);
        let mut string_ = Vec::new();
        plain(16, &mut string_);
        u32_bytes(1004, &mut inner);
        inner.extend(string_);
        inner.extend(opt);
    }
    let vec_ty = {
        let mut v = Vec::new();
        vec_of(&inner, &mut v);
        v
    };
    let mut result_ty = Vec::new();
    u32_bytes(1001, &mut result_ty);
    let mut i128 = Vec::new();
    plain(11, &mut i128);
    result_ty.extend(&i128);
    let mut tuple = Vec::new();
    u32_bytes(1005, &mut tuple);
    u32_bytes(2, &mut tuple);
    let mut u32_ = Vec::new();
    plain(4, &mut u32_);
    tuple.extend(&u32_);
    let mut bytesn = Vec::new();
    u32_bytes(1006, &mut bytesn);
    u32_bytes(32, &mut bytesn);
    tuple.extend(&bytesn);
    result_ty.extend(&tuple);

    let mut address = Vec::new();
    plain(19, &mut address);
    let mut spec = Vec::new();
    spec.extend(function(
        "allowance",
        &[&address, &vec_ty],
        Some(&result_ty),
    ));
    // Enough further names to clear the token-likeness floor.
    spec.extend(function("balance", &[&address], Some(&i128)));
    spec.extend(function("symbol", &[], None));

    let r = report_of(&spec);
    let d = deviation(&r).expect("deviation reported");
    let text = &d.facts["deviating_functions"];
    assert!(
        text.contains("allowance: expected fn(Address, Address) -> I128, reads fn(Address, Vec<Map<String,Option<Udt:Bal>>>) -> Result<I128,Tuple<U32,BytesN<32>>>"),
        "{text}"
    );
}

#[test]
fn non_function_entries_are_skipped_without_losing_the_functions() {
    // A real spec is mostly UDT and event entries. If any of their bodies were
    // mis-measured the following functions would decode as garbage, so the
    // conforming token must still raise nothing when they come first.
    let mut spec = Vec::new();
    // struct (kind 1): doc, lib, name, fields (doc, name, type)
    let mut st = Vec::new();
    u32_bytes(1, &mut st);
    xdr_string("", &mut st);
    xdr_string("lib", &mut st);
    xdr_string("Config", &mut st);
    u32_bytes(2, &mut st);
    for field in ["owner", "paused"] {
        xdr_string("docs", &mut st);
        xdr_string(field, &mut st);
        if field == "owner" {
            plain(19, &mut st);
        } else {
            plain(1, &mut st); // Bool
        }
    }
    spec.extend(st);
    // enum (kind 3): doc, lib, name, cases (doc, name, value)
    let mut en = Vec::new();
    u32_bytes(3, &mut en);
    xdr_string("", &mut en);
    xdr_string("lib", &mut en);
    xdr_string("Mode", &mut en);
    u32_bytes(2, &mut en);
    for (case, value) in [("A", 0u32), ("B", 1)] {
        xdr_string("", &mut en);
        xdr_string(case, &mut en);
        u32_bytes(value, &mut en);
    }
    spec.extend(en);
    // error enum (kind 4)
    let mut ee = Vec::new();
    u32_bytes(4, &mut ee);
    xdr_string("", &mut ee);
    xdr_string("lib", &mut ee);
    xdr_string("Err", &mut ee);
    u32_bytes(1, &mut ee);
    xdr_string("", &mut ee);
    xdr_string("NotAllowed", &mut ee);
    u32_bytes(1, &mut ee);
    spec.extend(ee);
    // union (kind 2) with both case arms
    let mut un = Vec::new();
    u32_bytes(2, &mut un);
    xdr_string("", &mut un);
    xdr_string("lib", &mut un);
    xdr_string("Choice", &mut un);
    u32_bytes(2, &mut un);
    u32_bytes(0, &mut un); // void case
    xdr_string("", &mut un);
    xdr_string("None", &mut un);
    u32_bytes(1, &mut un); // tuple case
    xdr_string("", &mut un);
    xdr_string("Some", &mut un);
    u32_bytes(1, &mut un);
    plain(11, &mut un);
    spec.extend(un);
    // event (kind 5): doc, lib, name, prefix topics, params, data format
    let mut ev = Vec::new();
    u32_bytes(5, &mut ev);
    xdr_string("", &mut ev);
    xdr_string("lib", &mut ev);
    xdr_string("Transfer", &mut ev);
    u32_bytes(1, &mut ev);
    xdr_string("transfer", &mut ev);
    u32_bytes(1, &mut ev);
    xdr_string("", &mut ev);
    xdr_string("amount", &mut ev);
    plain(11, &mut ev);
    u32_bytes(0, &mut ev); // location: data
    u32_bytes(1, &mut ev); // dataFormat: vec
    spec.extend(ev);

    spec.extend(conforming_token());
    let r = report_of(&spec);
    assert!(
        deviation(&r).is_none(),
        "UDT and event entries broke the walk: {:?}",
        r.indicators.iter().map(|i| i.code).collect::<Vec<_>>()
    );
}

#[test]
fn a_malformed_spec_is_no_claim_rather_than_an_empty_one() {
    let address = {
        let mut v = Vec::new();
        plain(19, &mut v);
        v
    };
    let mut good = conforming_token();
    // Truncate mid-entry: the walk cannot finish.
    good.truncate(good.len() - 3);
    let r = report_of(&good);
    assert!(r.claimed_meta.spec_present);
    assert!(deviation(&r).is_none(), "truncated spec must not compare");

    // A count that runs past the body.
    let mut inflated = function("symbol", &[&address], None);
    u32_bytes(0, &mut inflated);
    u32_bytes(4_000_000_000, &mut inflated); // array count, no bytes behind it
    let r = report_of(&inflated);
    assert!(deviation(&r).is_none());

    // An entry kind the pinned XDR does not define.
    let mut unknown = vec![0u8; 4];
    u32_bytes(99, &mut unknown);
    let mut spec = unknown;
    spec.extend(conforming_token());
    assert!(deviation(&report_of(&spec)).is_none());

    // A doc string longer than SCSPEC-DOC-LIMIT.
    let mut overlong = Vec::new();
    u32_bytes(0, &mut overlong); // function arm
    u32_bytes(5000, &mut overlong); // doc length
    overlong.extend(std::iter::repeat_n(b'x', 5000));
    let mut spec = overlong;
    spec.extend(conforming_token());
    assert!(deviation(&report_of(&spec)).is_none());

    // A name that is not an ASCII identifier cannot be shown to a user, so the
    // claim is dropped instead of escaping into a fact.
    let mut weird = Vec::new();
    u32_bytes(0, &mut weird);
    xdr_string("", &mut weird);
    xdr_string("sym\u{202e}ol", &mut weird);
    u32_bytes(0, &mut weird);
    u32_bytes(0, &mut weird);
    let mut spec = conforming_token();
    spec.extend(weird);
    assert!(
        deviation(&report_of(&spec)).is_none(),
        "bidi name must cancel the claim"
    );
}

#[test]
fn two_spec_sections_cancel_out_as_env_meta_does() {
    // Two sections can assert different signatures; picking one would be a
    // guess.
    let mut address = Vec::new();
    plain(19, &mut address);
    let mut i128 = Vec::new();
    plain(11, &mut i128);
    let deviating = function("transfer", &[&address, &address, &i128], None);
    let m = module(&[], &[], &[(SPEC, &conforming_token()), (SPEC, &deviating)]);
    let parsed = scan_core::parse::parse(&m).unwrap();
    assert_eq!(parsed.spec_bodies.len(), 2);
    assert!(scan_core::spec::signatures(&parsed.spec_bodies).is_none());
}

#[test]
fn an_oversized_spec_is_retained_empty_and_never_compared() {
    let mut blob = vec![0u8; scan_core::limits::MAX_SPEC_BYTES + 1];
    blob.extend(conforming_token());
    let m = module(&[], &[], &[(SPEC, &blob)]);
    let parsed = scan_core::parse::parse(&m).unwrap();
    assert_eq!(parsed.spec_bodies, vec![Vec::<u8>::new()]);
    assert!(scan_core::spec::signatures(&parsed.spec_bodies).is_none());
    let r = scan(&m, &KnownBadHashes::default()).unwrap();
    assert!(r.claimed_meta.spec_present);
    assert!(deviation(&r).is_none());
}

#[test]
fn nesting_beyond_the_depth_cap_cancels_the_claim() {
    let mut deep = Vec::new();
    for _ in 0..scan_core::limits::MAX_SPEC_DEPTH {
        u32_bytes(1000, &mut deep); // Option<Option<...>>
    }
    plain(19, &mut deep);
    let mut spec = function("allowance", &[&deep], None);
    spec.extend(function("balance", &[], None));
    spec.extend(function("symbol", &[], None));
    assert!(deviation(&report_of(&spec)).is_none());
}

#[test]
fn the_indicator_code_matches_the_reported_shape() {
    // A deviation must not be the only thing that changes: the code, the
    // informational flag and the sorted order are part of the contract Intel
    // consumes.
    let address = {
        let mut v = Vec::new();
        plain(19, &mut v);
        v
    };
    let mut spec = function("transfer", &[&address], None);
    spec.extend(function("balance", &[&address], None));
    spec.extend(function("symbol", &[&address], None));
    let r = report_of(&spec);
    let codes: Vec<&str> = r.indicators.iter().map(|i| i.code).collect();
    assert!(codes.contains(&"S-SEP41-DEVIATION"), "{codes:?}");
    assert_eq!(
        codes,
        {
            let mut c = codes.clone();
            c.sort_unstable();
            c
        },
        "indicators must stay code-sorted"
    );
    let d = deviation(&r).unwrap();
    assert!(d.informational);
    for (key, value) in &d.facts {
        assert!(
            value.len() <= 512 && !value.is_empty(),
            "fact {key} is outside the schema limit: {}",
            value.len()
        );
    }
}

#[test]
fn facts_never_carry_a_name_that_is_not_an_interface_name() {
    // Function names are untrusted. Only the ten baseline names and the
    // rendered type words may reach a fact.
    let address = {
        let mut v = Vec::new();
        plain(19, &mut v);
        v
    };
    let mut spec = Vec::new();
    for name in [
        "allowance",
        "balance",
        "symbol",
        "__constructor",
        "withdraw",
    ] {
        spec.extend(function(name, &[&address], None));
    }
    let r = report_of(&spec);
    let d = deviation(&r).unwrap();
    let joined: String = d.facts.values().cloned().collect::<Vec<_>>().join("|");
    assert!(!joined.contains("__constructor"), "{joined}");
    assert!(!joined.contains("withdraw"), "{joined}");
}
