use reqwest::header::HeaderValue;

#[inline]
pub fn parse_age_from_async_resp(resp: &reqwest::Response) -> u64 {
    parse_age_from_header(resp.headers().get("age"))
}

#[inline]
pub fn parse_max_age_from_async_resp(resp: &reqwest::Response) -> u64 {
    parse_max_age_from_header(resp.headers().get("cache-control"))
}

#[inline]
pub fn parse_age_from_resp(resp: &reqwest::blocking::Response) -> u64 {
    parse_age_from_header(resp.headers().get("age"))
}

#[inline]
pub fn parse_max_age_from_resp(resp: &reqwest::blocking::Response) -> u64 {
    parse_max_age_from_header(resp.headers().get("cache-control"))
}

fn parse_age_from_header(val: Option<&HeaderValue>) -> u64 {
    match val {
        Some(val) => val.to_str().unwrap_or("0").parse().unwrap_or_default(),
        None => 0,
    }
}

fn parse_max_age_from_header(val: Option<&HeaderValue>) -> u64 {
    match val {
        Some(val) => val
            .to_str()
            .unwrap_or("")
            .split(",")
            .map(|part| part.trim().to_lowercase())
            .find(|part| part.starts_with("max-age"))
            .map(|max_age| max_age.splitn(2, "=").last().unwrap_or("0").parse().unwrap_or_default())
            .unwrap_or_default(),
        None => 0,
    }
}
