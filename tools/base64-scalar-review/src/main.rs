use new::Engine as NewEngine;
use old::Engine as OldEngine;
use std::io::{Read, Write};
fn next(s: &mut u64) -> u8 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s as u8
}
fn main() {
    let oe = [
        old::engine::general_purpose::STANDARD,
        old::engine::general_purpose::STANDARD_NO_PAD,
        old::engine::general_purpose::URL_SAFE,
        old::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    let ne = [
        new::engine::general_purpose::STANDARD,
        new::engine::general_purpose::STANDARD_NO_PAD,
        new::engine::general_purpose::URL_SAFE,
        new::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    let mut seed = 0x123456789abcdefu64;
    let mut encodings = 0usize;
    let mut malformed = 0usize;
    for len in (0..=512).chain([1023, 1024, 1025, 4095, 4096, 4097]) {
        let input: Vec<u8> = (0..len).map(|_| next(&mut seed)).collect();
        for (o, n) in oe.iter().zip(ne.iter()) {
            let a = o.encode(&input);
            let b = n.encode(&input);
            assert_eq!(a, b);
            assert_eq!(o.decode(&a).unwrap(), n.decode(&b).unwrap());
            for extra in [0, 1, 16] {
                let mut ob = vec![0x5a; len + extra];
                let mut nb = ob.clone();
                let ol = o.decode_slice(&a, &mut ob).unwrap();
                let nl = n.decode_slice(&b, &mut nb).unwrap();
                assert_eq!(ol, nl);
                assert_eq!(&ob[..ol], &nb[..nl]);
                assert!(ob[ol..].iter().all(|b| *b == 0x5a));
                assert!(nb[nl..].iter().all(|b| *b == 0x5a));
                if len > 0 {
                    let mut short = vec![0; len - 1];
                    assert!(n.decode_slice(&b, &mut short).is_err());
                }
            }
            let mut od = old::read::DecoderReader::new(a.as_bytes(), o);
            let mut nd = new::read::DecoderReader::new(b.as_bytes(), n);
            let mut ov = Vec::new();
            let mut nv = Vec::new();
            od.read_to_end(&mut ov).unwrap();
            nd.read_to_end(&mut nv).unwrap();
            assert_eq!(ov, nv);
            assert_eq!(nv, input);
            for chunk in [1, 2, 3, 7, 31] {
                let mut ob = Vec::new();
                let mut nb = Vec::new();
                {
                    let mut ow = old::write::EncoderWriter::new(&mut ob, o);
                    let mut nw = new::write::EncoderWriter::new(&mut nb, n);
                    for c in input.chunks(chunk) {
                        ow.write_all(c).unwrap();
                        nw.write_all(c).unwrap();
                    }
                    ow.finish().unwrap();
                    nw.finish().unwrap();
                }
                assert_eq!(ob, nb);
                assert_eq!(nb, b.as_bytes());
            }
            encodings += 1;
        }
    }
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-! ";
    for case in 0..20000 {
        let len = case % 97;
        let bytes: Vec<u8> = (0..len)
            .map(|_| alphabet[next(&mut seed) as usize % alphabet.len()])
            .collect();
        for (o, n) in oe.iter().zip(ne.iter()) {
            let a = o.decode(&bytes);
            let b = n.decode(&bytes);
            assert_eq!(a.is_ok(), b.is_ok(), "acceptance differs: {:?}", bytes);
            if let (Ok(av), Ok(bv)) = (a, b) {
                assert_eq!(av, bv);
            }
            malformed += 1;
        }
    }
    for byte in 0..=255u8 {
        for suffix in [vec![b'Z', byte, b'=', b'='], vec![b'Z', b'm', byte, b'=']] {
            for (o, n) in oe.iter().zip(ne.iter()) {
                let a = o.decode(&suffix);
                let b = n.decode(&suffix);
                assert_eq!(a.is_ok(), b.is_ok());
                if let (Ok(a), Ok(b)) = (a, b) {
                    assert_eq!(a, b);
                }
                malformed += 1;
            }
        }
    }
    println!("PASS: {encodings} encode/decode/slice/stream scenarios; {malformed} malformed/trailing-bit comparisons; seed 0x123456789abcdef");
}
