//! Обёртка для чувствительных значений: zeroize при Drop, редакция в Debug/Display.

use std::fmt;
use zeroize::Zeroize;

/// Обёртка, гарантирующая затирание значения при уничтожении и не допускающая
/// случайной утечки через Debug/Display/Serialize.
pub struct Sensitive<T: Zeroize>(T);

impl<T: Zeroize + Clone> Clone for Sensitive<T> {
    fn clone(&self) -> Self {
        Sensitive(self.0.clone())
    }
}

impl<T: Zeroize + PartialEq> PartialEq for Sensitive<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Zeroize + Eq> Eq for Sensitive<T> {}

impl<T: Zeroize> Sensitive<T> {
    pub fn new(value: T) -> Self {
        Sensitive(value)
    }

    /// Доступ к значению. Только явный вызов.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<T: Zeroize> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<T: Zeroize> Drop for Sensitive<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> From<T> for Sensitive<T> {
    fn from(v: T) -> Self {
        Sensitive(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts() {
        let s = Sensitive::new(String::from("secret"));
        assert_eq!(format!("{:?}", s), "<redacted>");
        assert_eq!(format!("{}", s), "<redacted>");
        assert_eq!(s.expose(), "secret");
    }
}