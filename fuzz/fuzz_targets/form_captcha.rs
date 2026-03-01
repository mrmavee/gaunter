#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use gaunter::CaptchaManager;
use gaunter::Config;
use gaunter::test_helpers::parse_form;
use std::sync::{Arc, LazyLock};

#[derive(Arbitrary, Debug)]
struct WebInput {
    form_data: Vec<u8>,
    captcha_token: String,
    captcha_answer: String,
}

static CAPTCHA_MANAGER: LazyLock<Option<Arc<CaptchaManager>>> = LazyLock::new(|| {
    let config = Arc::new(Config::default());
    CaptchaManager::try_new(&config).ok().map(Arc::new)
});

fuzz_target!(|data: WebInput| {
    let _ = parse_form(&data.form_data);
    if let Some(manager) = CAPTCHA_MANAGER.as_ref() {
        let _ = manager.verify(&data.captcha_token, &data.captcha_answer);
    }
});
