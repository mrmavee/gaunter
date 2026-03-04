#![no_main]

use libfuzzer_sys::fuzz_target;
use gaunter::test_helpers::hs_setconf;

fuzz_target!(|data: &[u8]| {
    let Ok(torrc) = std::str::from_utf8(data) else {
        return;
    };
    let _ = hs_setconf(torrc, None, None);
    let _ = hs_setconf(torrc, Some(5), Some(10));
});
