#![no_main]

use libfuzzer_sys::fuzz_target;
use gaunter::test_helpers::parse_proxy_header;

use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct ProxyInput<'a> {
    prefix: &'a str,
    buf: &'a [u8],
}

fuzz_target!(|data: ProxyInput| {
    let _ = parse_proxy_header(data.buf, data.prefix);
});
