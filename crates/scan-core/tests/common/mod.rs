//! Synthetic modules are assembled byte by byte, so no real contract (and no
//! malware) is needed to exercise every indicator and hostile path.

pub fn leb(mut n: u32, out: &mut Vec<u8>) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

pub fn name(s: &str, out: &mut Vec<u8>) {
    leb(s.len() as u32, out);
    out.extend_from_slice(s.as_bytes());
}

pub fn section(id: u8, body: Vec<u8>, out: &mut Vec<u8>) {
    out.push(id);
    leb(body.len() as u32, out);
    out.extend(body);
}

/// A valid core module: function imports of type () -> (), exported no-op
/// functions, and custom sections at the end.
pub fn module(imports: &[(&str, &str)], exports: &[&str], customs: &[(&str, &[u8])]) -> Vec<u8> {
    let mut m = b"\0asm\x01\0\0\0".to_vec();
    section(1, vec![1, 0x60, 0, 0], &mut m);
    if !imports.is_empty() {
        let mut b = Vec::new();
        leb(imports.len() as u32, &mut b);
        for (module, field) in imports {
            name(module, &mut b);
            name(field, &mut b);
            b.extend([0x00, 0x00]); // func, type 0
        }
        section(2, b, &mut m);
    }
    if !exports.is_empty() {
        let mut funcs = Vec::new();
        leb(exports.len() as u32, &mut funcs);
        funcs.extend(std::iter::repeat_n(0u8, exports.len()));
        section(3, funcs, &mut m);
        let mut ex = Vec::new();
        leb(exports.len() as u32, &mut ex);
        for (i, e) in exports.iter().enumerate() {
            name(e, &mut ex);
            ex.push(0x00);
            leb((imports.len() + i) as u32, &mut ex);
        }
        section(7, ex, &mut m);
        let mut code = Vec::new();
        leb(exports.len() as u32, &mut code);
        for _ in exports {
            code.extend([2, 0, 0x0b]); // size, no locals, end
        }
        section(10, code, &mut m);
    }
    for (n, data) in customs {
        let mut b = Vec::new();
        name(n, &mut b);
        b.extend_from_slice(data);
        section(0, b, &mut m);
    }
    m
}
