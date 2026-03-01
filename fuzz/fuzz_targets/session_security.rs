#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use gaunter::test_helpers::{CookieCrypto, EncryptedSession};

#[derive(Arbitrary, Debug)]
struct SessionInput<'a> {
    secret: &'a str,
    data: &'a [u8],
}

fuzz_target!(|input: SessionInput| {
    if input.secret.is_empty() {
        return;
    }

    let crypto = CookieCrypto::new(input.secret);

    if let Ok(encoded) = std::str::from_utf8(input.data) {
        let _ = crypto.decrypt(encoded);
    }

    let _ = EncryptedSession::from_bytes(input.data, 3600);

    if let Ok(encrypted) = crypto.try_encrypt(input.data)
        && let Some(decrypted_bytes) = crypto.decrypt(&encrypted)
    {
        assert_eq!(input.data, decrypted_bytes, "Round-trip encryption failure");
    }
});
