//! Helpers shared by the integration tests.

/// The value of `key` in the query string of `url`.
#[allow(
    clippy::unwrap_used,
    reason = "test helper: a missing value is a test failure, reported by the panic"
)]
pub fn query_value(url: &str, key: &str) -> String {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .unwrap()
}
