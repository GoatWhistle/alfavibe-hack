//! Подсчёт токенов.

use crate::domain::traits::TokenCounter;

/// Быстрый аппроксиматор токенов: слова + знаки препинания, коэффициент 1.3 для кириллицы.
pub struct ApproxTokenCounter {
    cyrillic_factor: f32,
}

impl Default for ApproxTokenCounter {
    fn default() -> Self {
        Self {
            cyrillic_factor: 1.3,
        }
    }
}

impl TokenCounter for ApproxTokenCounter {
    fn count(&self, text: &str) -> usize {
        let mut tokens = 0usize;
        let mut in_word = false;
        let mut cyrillic_chars = 0usize;
        let mut total_chars = 0usize;

        for ch in text.chars() {
            total_chars += 1;
            if ch.is_alphabetic() {
                if !in_word {
                    tokens += 1;
                    in_word = true;
                }
                if ('а'..='я').contains(&ch) || ('А'..='Я').contains(&ch) {
                    cyrillic_chars += 1;
                }
            } else if ch.is_whitespace() {
                in_word = false;
            } else {
                // знак препинания — отдельный токен
                tokens += 1;
                in_word = false;
            }
        }

        let cyrillic_ratio = if total_chars == 0 {
            0.0
        } else {
            cyrillic_chars as f32 / total_chars as f32
        };
        let factor = if cyrillic_ratio > 0.3 {
            self.cyrillic_factor
        } else {
            1.0
        };
        (tokens as f32 * factor).round() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_words() {
        let c = ApproxTokenCounter::default();
        assert!(c.count("hello world") >= 2);
        assert!(c.count("привет мир") >= 2);
    }
}