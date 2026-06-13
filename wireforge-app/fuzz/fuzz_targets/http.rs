#![no_main]
use libfuzzer_sys::fuzz_target;
use wireforge_app::http::{HttpRequest, HttpResponse};

fuzz_target!(|data: &[u8]| {
    if let Some(req) = HttpRequest::parse(data) {
        let _ = req.method();
        let _ = req.uri();
        for _ in req.headers() {}
    }
    if let Some(resp) = HttpResponse::parse(data) {
        let _ = resp.status_code();
        let _ = resp.reason();
        for _ in resp.headers() {}
    }
});
