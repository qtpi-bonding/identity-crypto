/// The audience a request is signed for: `"<service>:<method>@<server id>"`.
/// The method is inside the signed audience, so a signature cannot be replayed
/// on another method, nor on another service, even with the same body.
pub fn audience_for(service: &str, method: &str, server_id: &str) -> String {
    format!("{service}:{method}@{server_id}")
}

/// Splits a gRPC path `"/<service>/<method>"` into `(service, method)`.
pub fn split_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix('/')?;
    let (service, method) = rest.split_once('/')?;
    if service.is_empty() || method.is_empty() || method.contains('/') {
        return None;
    }
    Some((service, method))
}
