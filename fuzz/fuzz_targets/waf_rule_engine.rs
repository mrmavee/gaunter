#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use gaunter::test_helpers::RuleEngine;
use std::sync::LazyLock;

static ENGINE: LazyLock<RuleEngine> = LazyLock::new(|| RuleEngine::try_new().unwrap());

#[derive(Arbitrary, Debug)]
struct WafInput<'a> {
    path: &'a str,
    query: &'a str,
    body: &'a str,
    cookie: &'a str,
}

fuzz_target!(|input: WafInput| {
    let _ = ENGINE.eval(input.path, input.query, input.body, input.cookie);
});
