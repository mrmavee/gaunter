#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use gaunter::test_helpers::detect_safe_mime;

#[derive(Arbitrary, Debug)]
struct MimeInput<'a> {
    prefix_junk: &'a [u8],
    magic_payload: &'a [u8],
    suffix_junk: &'a [u8],
}

fuzz_target!(|input: MimeInput| {
    let mut combined = Vec::with_capacity(
        input.prefix_junk.len() + input.magic_payload.len() + input.suffix_junk.len(),
    );
    combined.extend_from_slice(input.prefix_junk);
    combined.extend_from_slice(input.magic_payload);
    combined.extend_from_slice(input.suffix_junk);

    let _ = detect_safe_mime(&combined);
    let _ = detect_safe_mime(input.magic_payload);
});
