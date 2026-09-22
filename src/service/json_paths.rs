//! Минимальный синтаксис JSON-путей: `$`, `.key`, `["key"]`, `[*]`, `[n]`.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub enum PathSegment {
    Key(String),
    Index(usize),
    All,
}

pub type Path = Vec<PathSegment>;

/// Парсит путь вида `$.messages[*].content`.
pub fn parse_path(s: &str) -> Option<Path> {
    let s = s.trim();
    if !s.starts_with('$') {
        return None;
    }
    let rest = &s[1..];
    let mut path = Vec::new();
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'.' => {
                i += 1;
                // ключ до следующего '.' или '['
                let start = i;
                while i < bytes.len() && bytes[i] != b'.' && bytes[i] != b'[' {
                    i += 1;
                }
                if i > start {
                    path.push(PathSegment::Key(rest[start..i].to_string()));
                }
            }
            b'[' => {
                i += 1;
                if i < bytes.len() && bytes[i] == b'"' {
                    // ["key"]
                    i += 1;
                    let start = i;
                    while i < bytes.len() && bytes[i] != b'"' {
                        i += 1;
                    }
                    if i >= bytes.len() {
                        return None;
                    }
                    path.push(PathSegment::Key(rest[start..i].to_string()));
                    i += 1; // closing quote
                    if i < bytes.len() && bytes[i] == b']' {
                        i += 1;
                    }
                } else if i < bytes.len() && bytes[i] == b'*' {
                    path.push(PathSegment::All);
                    i += 1;
                    if i < bytes.len() && bytes[i] == b']' {
                        i += 1;
                    }
                } else {
                    // [n]
                    let start = i;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    if i > start {
                        let n: usize = rest[start..i].parse().ok()?;
                        path.push(PathSegment::Index(n));
                    }
                    if i < bytes.len() && bytes[i] == b']' {
                        i += 1;
                    }
                }
            }
            _ => {
                i += 1;
            }
        }
    }
    Some(path)
}

/// Извлекает все строки по пути.
pub fn extract<'a>(value: &'a Value, path: &Path) -> Vec<&'a str> {
    let mut out = Vec::new();
    extract_rec(value, path, 0, &mut out);
    out
}

fn extract_rec<'a>(value: &'a Value, path: &Path, idx: usize, out: &mut Vec<&'a str>) {
    if idx == path.len() {
        if let Value::String(s) = value {
            out.push(s);
        }
        return;
    }
    match &path[idx] {
        PathSegment::Key(k) => {
            if let Value::Object(map) = value {
                if let Some(v) = map.get(k) {
                    extract_rec(v, path, idx + 1, out);
                }
            }
        }
        PathSegment::Index(n) => {
            if let Value::Array(arr) = value {
                if let Some(v) = arr.get(*n) {
                    extract_rec(v, path, idx + 1, out);
                }
            }
        }
        PathSegment::All => {
            if let Value::Array(arr) = value {
                for v in arr {
                    extract_rec(v, path, idx + 1, out);
                }
            }
        }
    }
}

/// Заменяет строки по пути через функцию f.
pub fn replace<F>(value: &mut Value, path: &Path, f: &mut F)
where
    F: FnMut(&str) -> String,
{
    replace_rec(value, path, 0, f);
}

/// Асинхронная замена строк по пути.
pub async fn replace_async<F, Fut>(value: &mut Value, path: &Path, f: &mut F)
where
    F: FnMut(&str) -> Fut + Send,
    Fut: std::future::Future<Output = String> + Send,
{
    replace_async_rec(value, path, 0, f).await;
}

fn replace_async_rec<'a, F, Fut>(
    value: &'a mut Value,
    path: &'a Path,
    idx: usize,
    f: &'a mut F,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>
where
    F: FnMut(&str) -> Fut + Send + 'a,
    Fut: std::future::Future<Output = String> + Send + 'a,
{
    Box::pin(async move {
        if idx == path.len() {
            if let Value::String(s) = value {
                let new = f(s).await;
                *value = Value::String(new);
            }
            return;
        }
        match &path[idx] {
            PathSegment::Key(k) => {
                if let Value::Object(map) = value {
                    if let Some(v) = map.get_mut(k) {
                        replace_async_rec(v, path, idx + 1, f).await;
                    }
                }
            }
            PathSegment::Index(n) => {
                if let Value::Array(arr) = value {
                    if let Some(v) = arr.get_mut(*n) {
                        replace_async_rec(v, path, idx + 1, f).await;
                    }
                }
            }
            PathSegment::All => {
                if let Value::Array(arr) = value {
                    for v in arr.iter_mut() {
                        replace_async_rec(v, path, idx + 1, f).await;
                    }
                }
            }
        }
    })
}

fn replace_rec<F>(value: &mut Value, path: &Path, idx: usize, f: &mut F)
where
    F: FnMut(&str) -> String,
{
    if idx == path.len() {
        if let Value::String(s) = value {
            *value = Value::String(f(s));
        }
        return;
    }
    match &path[idx] {
        PathSegment::Key(k) => {
            if let Value::Object(map) = value {
                if let Some(v) = map.get_mut(k) {
                    replace_rec(v, path, idx + 1, f);
                }
            }
        }
        PathSegment::Index(n) => {
            if let Value::Array(arr) = value {
                if let Some(v) = arr.get_mut(*n) {
                    replace_rec(v, path, idx + 1, f);
                }
            }
        }
        PathSegment::All => {
            if let Value::Array(arr) = value {
                for v in arr.iter_mut() {
                    replace_rec(v, path, idx + 1, f);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_and_extract() {
        let v = json!({
            "messages": [
                {"content": "hello"},
                {"content": "world"}
            ]
        });
        let path = parse_path("$.messages[*].content").unwrap();
        let strs = extract(&v, &path);
        assert_eq!(strs, vec!["hello", "world"]);
    }

    #[test]
    fn parse_bracket_key() {
        let v = json!({"a.b": "x"});
        let path = parse_path("$[\"a.b\"]").unwrap();
        assert_eq!(extract(&v, &path), vec!["x"]);
    }

    #[test]
    fn replace_works() {
        let mut v = json!({"messages": [{"content": "hello"}]});
        let path = parse_path("$.messages[*].content").unwrap();
        replace(&mut v, &path, &mut |s| s.to_uppercase());
        assert_eq!(v["messages"][0]["content"], "HELLO");
    }
}