//! The `contractspecv0` custom section: the function and type signatures the
//! contract's author says it exposes. The network does not check it, so every
//! value read here is a claim, and an unreadable claim is reported as no claim.
//!
//! Wire shape verified against two primary sources, not assumed:
//! - go-stellar-sdk v0.7.3 `xdr/Stellar-contract-spec.x`: `SCSpecEntry` is a
//!   union on `kind` (0 function, 1 struct, 2 union, 3 enum, 4 error enum,
//!   5 event), and `SCSpecTypeDef` is a union on `type` whose parameterised
//!   arms are 1000 option, 1001 result, 1002 vec, 1004 map, 1005 tuple (max 12
//!   members), 1006 bytes_n, 2000 udt.
//! - 61 distinct contract modules deployed in 6000 testnet ledgers, read from
//!   ledger metadata on 2026-10-29: decoding the section as a bare sequence of
//!   `SCSpecEntry` values consumed every body exactly to its end (61/61), while
//!   reading it as an XDR array with a leading count failed on all 61. So the
//!   section is a concatenation, not an array. Observed maxima in that sample:
//!   28,056 bytes, 117 entries, type nesting depth 3.

use crate::limits::{MAX_SPEC_BYTES, MAX_SPEC_DEPTH, MAX_SPEC_ENTRIES, MAX_SPEC_STRINGS};

pub const SPEC_SECTION: &str = "contractspecv0";

/// A function the module claims to expose: its name, its positional input type
/// names, and its single declared output type name when it declares one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSig {
    pub name: String,
    pub inputs: Vec<String>,
    pub output: Option<String>,
}

/// Smallest legal encoding of one `SCSpecFunctionInputV0` or struct field:
/// empty doc, empty name, plain type tag. Used to reject a hostile array count
/// without rejecting a real spec, so it must stay at the true minimum.
const FUNC_INPUT_MIN_BYTES: usize = 12;
/// One union or enum case with no payload: kind or doc, name, value.
const CASE_MIN_BYTES: usize = 12;
/// One event parameter: doc, name, plain type tag, location tag.
const EVENT_PARAM_MIN_BYTES: usize = 16;

/// `SCSpecEntry` arm tags.
const ENTRY_FUNCTION: u32 = 0;
const ENTRY_UDT_STRUCT: u32 = 1;
const ENTRY_UDT_UNION: u32 = 2;
const ENTRY_UDT_ENUM: u32 = 3;
const ENTRY_UDT_ERROR_ENUM: u32 = 4;
const ENTRY_EVENT: u32 = 5;

/// `SCSpecType` tags that carry no payload. `SC_SPEC_TYPE_VAL` is 0 and the
/// list skips 15 and 18, which the pinned spec does not define.
const PLAIN_TYPES: [(u32, &str); 19] = [
    (0, "Val"),
    (1, "Bool"),
    (2, "Void"),
    (3, "Error"),
    (4, "U32"),
    (5, "I32"),
    (6, "U64"),
    (7, "I64"),
    (8, "Timepoint"),
    (9, "Duration"),
    (10, "U128"),
    (11, "I128"),
    (12, "U256"),
    (13, "I256"),
    (14, "Bytes"),
    (16, "String"),
    (17, "Symbol"),
    (19, "Address"),
    (20, "MuxedAddress"),
];

/// SEP-41 `TokenInterface`, checked 2026-10-29 against both the SEP text
/// (version 0.5.2, updated 2026-08-24) and `soroban-sdk/src/token.rs`
/// `TokenInterface` on rs-soroban-sdk main. The two agree on these ten
/// functions and these signatures. `total`, `spendable_balance`, `mint`,
/// `clawback` and the admin functions are not in the interface, so they are
/// not required here; `transfer`'s destination is `MuxedAddress` in both,
/// which is why a plain `Address` destination reads as a deviation.
pub const SEP41: [(&str, &[&str], Option<&str>); 10] = [
    ("allowance", &["Address", "Address"], Some("I128")),
    ("approve", &["Address", "Address", "I128", "U32"], None),
    ("balance", &["Address"], Some("I128")),
    ("transfer", &["Address", "MuxedAddress", "I128"], None),
    (
        "transfer_from",
        &["Address", "Address", "Address", "I128"],
        None,
    ),
    ("burn", &["Address", "I128"], None),
    ("burn_from", &["Address", "Address", "I128"], None),
    ("decimals", &[], Some("U32")),
    ("name", &[], Some("String")),
    ("symbol", &[], Some("String")),
];

/// A module is read as claiming to be a token once it declares at least this
/// many of the ten interface names. The floor is a rule choice, so it is
/// stated with its evidence: measured 2026-10-29 across the 61 distinct
/// testnet modules above, 58 declared none of the ten, 2 declared exactly one
/// (both `name`, a generic function name), and the one real token declared all
/// ten. Three sits in that gap: above the noise, far below a token's ten.
pub const TOKEN_LIKE_MIN_NAMES: usize = 3;

/// What the module claims about SEP-41, from its own function list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sep41Claim {
    /// How many of the ten interface names the module declares: the basis on
    /// which it was read as a token claim at all.
    pub declared: usize,
    /// Interface names it does not declare at all.
    pub missing: Vec<&'static str>,
    /// Declared names whose positional types or output differ, as
    /// `(name, expected, observed)`.
    pub mismatched: Vec<(String, String, String)>,
}

/// The one claim a module makes, if it makes exactly one that can be read.
/// Two sections assert different signatures and cancel out, as in `crate::meta`.
pub fn signatures(bodies: &[Vec<u8>]) -> Option<Vec<FunctionSig>> {
    let [body] = bodies else {
        return None;
    };
    // An oversized body is retained as empty by `crate::parse`, and an empty
    // section is not a readable claim.
    if body.is_empty() || body.len() > MAX_SPEC_BYTES {
        return None;
    }
    read_entries(body)
}

/// Reads the entry sequence and keeps the claimed functions. Anything that
/// cannot be followed - unknown arm, over-long string, count beyond the
/// remaining bytes, depth or count past a cap, trailing bytes - is `None`.
fn read_entries(body: &[u8]) -> Option<Vec<FunctionSig>> {
    let mut r = Reader {
        b: body,
        i: 0,
        depth: 0,
        entries: 0,
        strings: 0,
    };
    let mut out = Vec::new();
    while r.i < body.len() {
        if r.entries >= MAX_SPEC_ENTRIES {
            return None;
        }
        r.entries += 1;
        if let Some(sig) = r.entry()? {
            out.push(sig);
        }
    }
    Some(out)
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
    depth: u32,
    entries: u32,
    strings: u32,
}

impl Reader<'_> {
    fn u32(&mut self) -> Option<u32> {
        let n = u32::from_be_bytes(self.take(4)?.try_into().ok()?);
        Some(n)
    }

    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.i.checked_add(n)?;
        if end > self.b.len() {
            return None;
        }
        let s = &self.b[self.i..end];
        self.i = end;
        Some(s)
    }

    /// A bounded XDR `string<max>`, padded to 4 bytes. Over-long or truncated
    /// is a malformed claim.
    fn string(&mut self, max: usize) -> Option<String> {
        self.strings += 1;
        if self.strings > MAX_SPEC_STRINGS {
            return None;
        }
        let len = self.u32()? as usize;
        if len > max {
            return None;
        }
        let bytes = self.take(len)?.to_vec();
        let pad = (4 - len % 4) % 4;
        if pad > 0 && self.take(pad).is_none() {
            return None;
        }
        // Claims reach only indicator facts, so non-UTF-8 is unreadable, not
        // something to lossily repair.
        String::from_utf8(bytes).ok()
    }

    /// A claimed name. These reach indicator facts, so anything outside an
    /// ASCII identifier makes the claim unreadable rather than carrying
    /// control, bidi or non-ASCII characters towards a user (AGENTS.md §5).
    /// Real Soroban function and type names are Rust identifiers.
    fn ident(&mut self, max: usize) -> Option<String> {
        let s = self.string(max)?;
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return None;
        }
        Some(s)
    }

    /// The element count of an XDR array, checked against what is left so a
    /// hostile count cannot run the reader past the body.
    fn array_len(&mut self, min_element: usize, cap: u32) -> Option<usize> {
        let n = self.u32()?;
        if n > cap || (min_element > 0 && n as usize * min_element > self.b.len() - self.i) {
            return None;
        }
        Some(n as usize)
    }

    /// `SCSpecTypeDef`, rendered as a short name. Recursion is depth-capped.
    fn type_name(&mut self) -> Option<String> {
        if self.depth >= MAX_SPEC_DEPTH {
            return None;
        }
        self.depth += 1;
        let name = self.type_name_inner();
        self.depth -= 1;
        name
    }

    fn type_name_inner(&mut self) -> Option<String> {
        let tag = self.u32()?;
        if let Some((_, n)) = PLAIN_TYPES.iter().find(|(t, _)| *t == tag) {
            return Some((*n).to_owned());
        }
        match tag {
            1000 => Some(format!("Option<{}>", self.type_name()?)),
            1001 => {
                let ok = self.type_name()?;
                let err = self.type_name()?;
                Some(format!("Result<{ok},{err}>"))
            }
            1002 => Some(format!("Vec<{}>", self.type_name()?)),
            1004 => {
                let k = self.type_name()?;
                let v = self.type_name()?;
                Some(format!("Map<{k},{v}>"))
            }
            1005 => {
                let n = self.array_len(4, 12)?;
                let mut parts = Vec::with_capacity(n);
                for _ in 0..n {
                    parts.push(self.type_name()?);
                }
                Some(format!("Tuple<{}>", parts.join(",")))
            }
            1006 => Some(format!("BytesN<{}>", self.u32()?)),
            2000 => Some(format!("Udt:{}", self.ident(60)?)),
            // An unlisted tag is a spec newer than the pinned XDR. Guessing a
            // size for its payload would misread every entry after it.
            _ => None,
        }
    }

    /// One `SCSpecEntry`. Returns the claim only for function arms.
    fn entry(&mut self) -> Option<Option<FunctionSig>> {
        match self.u32()? {
            ENTRY_FUNCTION => {
                let _doc = self.string(1024)?;
                let name = self.ident(32)?;
                let n = self.array_len(FUNC_INPUT_MIN_BYTES, MAX_SPEC_ENTRIES)?;
                let mut inputs = Vec::with_capacity(n);
                for _ in 0..n {
                    let _doc = self.string(1024)?;
                    let _arg = self.string(30)?;
                    inputs.push(self.type_name()?);
                }
                // `outputs<1>`: zero or one.
                let out_n = self.array_len(4, 1)?;
                let output = if out_n == 1 {
                    Some(self.type_name()?)
                } else {
                    None
                };
                Some(Some(FunctionSig {
                    name,
                    inputs,
                    output,
                }))
            }
            ENTRY_UDT_STRUCT => {
                let _doc = self.string(1024)?;
                let _lib = self.string(80)?;
                let _name = self.string(60)?;
                let n = self.array_len(FUNC_INPUT_MIN_BYTES, MAX_SPEC_ENTRIES)?;
                for _ in 0..n {
                    let _doc = self.string(1024)?;
                    let _field = self.string(30)?;
                    let _t = self.type_name()?;
                }
                Some(None)
            }
            ENTRY_UDT_UNION => {
                let _doc = self.string(1024)?;
                let _lib = self.string(80)?;
                let _name = self.string(60)?;
                let n = self.array_len(CASE_MIN_BYTES, MAX_SPEC_ENTRIES)?;
                for _ in 0..n {
                    match self.u32()? {
                        0 => {
                            let _doc = self.string(1024)?;
                            let _case = self.string(60)?;
                        }
                        1 => {
                            let _doc = self.string(1024)?;
                            let _case = self.string(60)?;
                            let m = self.array_len(4, MAX_SPEC_ENTRIES)?;
                            for _ in 0..m {
                                let _t = self.type_name()?;
                            }
                        }
                        _ => return None,
                    }
                }
                Some(None)
            }
            ENTRY_UDT_ENUM | ENTRY_UDT_ERROR_ENUM => {
                let _doc = self.string(1024)?;
                let _lib = self.string(80)?;
                let _name = self.string(60)?;
                let n = self.array_len(CASE_MIN_BYTES, MAX_SPEC_ENTRIES)?;
                for _ in 0..n {
                    let _doc = self.string(1024)?;
                    let _case = self.string(60)?;
                    let _value = self.u32()?;
                }
                Some(None)
            }
            ENTRY_EVENT => {
                let _doc = self.string(1024)?;
                let _lib = self.string(80)?;
                let _name = self.string(32)?;
                let n = self.array_len(4, 2)?;
                for _ in 0..n {
                    let _topic = self.string(32)?;
                }
                let n = self.array_len(EVENT_PARAM_MIN_BYTES, MAX_SPEC_ENTRIES)?;
                for _ in 0..n {
                    let _doc = self.string(1024)?;
                    let _param = self.string(30)?;
                    let _t = self.type_name()?;
                    if !matches!(self.u32()?, 0 | 1) {
                        return None;
                    }
                }
                if !matches!(self.u32()?, 0..=2) {
                    return None;
                }
                Some(None)
            }
            // Unknown entry kind: the size of its body is not knowable, so the
            // rest of the section cannot be read either.
            _ => None,
        }
    }
}

/// Compares a claimed function list with `SEP41`. `None` means the module does
/// not read as a token claim, so there is nothing to compare and nothing to
/// report; it is not a statement that it conforms.
pub fn sep41_claim(functions: &[FunctionSig]) -> Option<Sep41Claim> {
    let declared = SEP41
        .iter()
        .filter(|(name, _, _)| functions.iter().any(|f| f.name == *name))
        .count();
    if declared < TOKEN_LIKE_MIN_NAMES {
        return None;
    }
    let mut claim = Sep41Claim {
        declared,
        missing: Vec::new(),
        mismatched: Vec::new(),
    };
    for &(name, inputs, output) in SEP41.iter() {
        let matches: Vec<&FunctionSig> = functions.iter().filter(|f| f.name == name).collect();
        if matches.is_empty() {
            claim.missing.push(name);
            continue;
        }
        // A name declared more than once is only a deviation when no
        // declaration matches the interface; if one does, the interface is
        // present and picking between the rest would be a guess.
        if matches.iter().any(|f| conforms(f, inputs, output)) {
            continue;
        }
        let expected = render(inputs, output);
        let observed = matches
            .iter()
            .map(|f| render(&f.inputs, f.output.as_deref()))
            .min()
            .unwrap_or_default();
        claim.mismatched.push((name.to_owned(), expected, observed));
    }
    claim.missing.sort_unstable();
    claim.mismatched.sort_by(|a, b| a.0.cmp(&b.0));
    if claim.missing.is_empty() && claim.mismatched.is_empty() {
        return None;
    }
    Some(claim)
}

fn conforms(f: &FunctionSig, inputs: &[&str], output: Option<&str>) -> bool {
    let args: Vec<&str> = f.inputs.iter().map(String::as_str).collect();
    args == inputs && f.output.as_deref() == output
}

fn render(inputs: &[impl AsRef<str>], output: Option<&str>) -> String {
    let mut s = format!(
        "fn({})",
        inputs
            .iter()
            .map(|t| t.as_ref())
            .collect::<Vec<_>>()
            .join(", ")
    );
    match output {
        Some(o) => {
            s.push_str(" -> ");
            s.push_str(o);
        }
        None => s.push_str(" -> void"),
    }
    s
}
