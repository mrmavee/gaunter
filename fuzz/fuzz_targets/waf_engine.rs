#![no_main]

use libfuzzer_sys::fuzz_target;
use gaunter::Config;
use gaunter::WafEngine;
use gaunter::WebhookNotifier;
use std::sync::{Arc, LazyLock};

use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct WafInput {
    input: String,
    location: String,
}

static WAF_ENGINE: LazyLock<Option<Arc<WafEngine>>> = LazyLock::new(|| {
    let config = Arc::new(Config::default());
    let webhook = Arc::new(WebhookNotifier::new(&config));
    WafEngine::try_new(webhook, vec![]).ok().map(Arc::new)
});

fuzz_target!(|data: WafInput| {
    if let Some(engine) = WAF_ENGINE.as_ref() {
        let _ = engine.scan(&data.input, &data.location);
    }
});
