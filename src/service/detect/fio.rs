//! Детектор ФИО (FIO) — словарный, с токенизацией и шаблонами.

use std::collections::HashSet;

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, DetectorSource, SignalFlags};
use crate::domain::pd_type::PdType;
use crate::domain::traits::{DetectCtx, Detector};
use crate::service::detect::context::window;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TokFlags: u32 {
        const NAME = 1 << 0;
        const PATRONYMIC = 1 << 1;
        const SURNAME_SHAPE = 1 << 2;
        const INITIALS = 1 << 3;
        const CAPITALIZED = 1 << 4;
    }
}

struct Token {
    start: usize,
    end: usize,
    flags: TokFlags,
}

pub struct FioDetector {
    first_names: HashSet<String>,
    types: Vec<PdType>,
}

impl FioDetector {
    pub fn new(first_names: Vec<String>) -> Self {
        Self {
            first_names: first_names.into_iter().collect(),
            types: vec![PdType::new(PdType::FIO)],
        }
    }

    fn tokenize(&self, doc: &Document<'_>) -> Vec<Token> {
        let norm = &doc.norm;
        let mut tokens = Vec::new();
        let mut i = 0;
        let bytes = norm.as_bytes();
        while i < bytes.len() {
            if bytes[i].is_ascii_whitespace() || bytes[i] == b',' {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b',' {
                i += 1;
            }
            let word = &norm[start..i];
            let mut flags = TokFlags::empty();

            // Инициалы: [а-я]. [а-я].
            if is_initials(word) {
                flags |= TokFlags::INITIALS;
            }

            // Имя из словаря
            if self.first_names.contains(word) {
                flags |= TokFlags::NAME;
            }

            // Отчество
            if is_patronymic(word) {
                flags |= TokFlags::PATRONYMIC;
            }

            // Фамилия по форме
            if is_surname_shape(word) {
                flags |= TokFlags::SURNAME_SHAPE;
            }

            // Заглавная в оригинале
            let orig = doc.original_slice(doc.to_original(start, i));
            if orig.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                flags |= TokFlags::CAPITALIZED;
            }

            if !flags.is_empty() {
                tokens.push(Token { start, end: i, flags });
            }
        }
        tokens
    }
}

fn is_initials(word: &str) -> bool {
    let chars: Vec<char> = word.chars().collect();
    chars.len() == 4 && chars[1] == '.' && chars[3] == '.'
}

fn is_patronymic(word: &str) -> bool {
    let suffixes = [
        "ович", "евич", "ич", "овна", "евна", "ична", "инична",
        "овича", "евича", "ича", "овны", "евны", "ичны",
        "овичу", "евичу", "ичу", "овной", "евной", "ичной",
        "овичем", "евичем", "ичем", "овне", "евне", "ичне",
        "оглы", "кызы", "улы",
    ];
    suffixes.iter().any(|s| word.ends_with(s))
}

fn is_surname_shape(word: &str) -> bool {
    let suffixes = [
        "ов", "ев", "ёв", "ин", "ын", "ский", "цкий", "ской", "цкой",
        "ова", "ева", "ина", "ына", "ская", "цкая", "енко", "ук", "юк",
        "ян", "дзе", "швили", "их", "ых", "ко",
        "ову", "еву", "ину", "ыну", "овым", "евым", "иным", "ыным",
        "ове", "еве", "ине", "ыне", "овой", "евой", "иной", "ыной",
    ];
    suffixes.iter().any(|s| word.ends_with(s))
}

impl Detector for FioDetector {
    fn id(&self) -> &str {
        "fio"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        let tokens = self.tokenize(doc);
        let n = tokens.len();
        let mut i = 0;
        while i < n {
            let t = &tokens[i];
            let flags = t.flags;

            // SURNAME NAME PATRONYMIC
            if i + 2 < n {
                let (a, b, c) = (&tokens[i], &tokens[i + 1], &tokens[i + 2]);
                if a.flags.contains(TokFlags::SURNAME_SHAPE)
                    && b.flags.contains(TokFlags::NAME)
                    && c.flags.contains(TokFlags::PATRONYMIC)
                    && are_adjacent(doc, a, b)
                    && are_adjacent(doc, b, c)
                {
                    push_fio(doc, out, a.start, c.end, 0.95);
                    i += 3;
                    continue;
                }
                // NAME PATRONYMIC SURNAME
                if a.flags.contains(TokFlags::NAME)
                    && b.flags.contains(TokFlags::PATRONYMIC)
                    && c.flags.contains(TokFlags::SURNAME_SHAPE)
                    && are_adjacent(doc, a, b)
                    && are_adjacent(doc, b, c)
                {
                    push_fio(doc, out, a.start, c.end, 0.95);
                    i += 3;
                    continue;
                }
            }

            // NAME PATRONYMIC
            if i + 1 < n {
                let (a, b) = (&tokens[i], &tokens[i + 1]);
                if a.flags.contains(TokFlags::NAME)
                    && b.flags.contains(TokFlags::PATRONYMIC)
                    && are_adjacent(doc, a, b)
                {
                    push_fio(doc, out, a.start, b.end, 0.95);
                    i += 2;
                    continue;
                }
                // SURNAME INITIALS / INITIALS SURNAME
                if ((a.flags.contains(TokFlags::SURNAME_SHAPE) && b.flags.contains(TokFlags::INITIALS))
                    || (a.flags.contains(TokFlags::INITIALS) && b.flags.contains(TokFlags::SURNAME_SHAPE)))
                    && are_adjacent(doc, a, b)
                {
                    push_fio(doc, out, a.start, b.end, 0.9);
                    i += 2;
                    continue;
                }
                // NAME SURNAME / SURNAME NAME
                if ((a.flags.contains(TokFlags::NAME) && b.flags.contains(TokFlags::SURNAME_SHAPE))
                    || (a.flags.contains(TokFlags::SURNAME_SHAPE) && b.flags.contains(TokFlags::NAME)))
                    && are_adjacent(doc, a, b)
                {
                    let mut score = 0.8;
                    if a.flags.contains(TokFlags::CAPITALIZED) && b.flags.contains(TokFlags::CAPITALIZED) {
                        score += 0.1;
                    }
                    push_fio(doc, out, a.start, b.end, score);
                    i += 2;
                    continue;
                }
            }

            // одиночная фамилия с контекстом
            if flags.contains(TokFlags::SURNAME_SHAPE) {
                let window = window(doc, t.start.saturating_sub(60), t.end + 20);
                let has_context = ["клиент", "гражданин", "господин", "г-н", "г-жа", "фамилия", "фио", "заемщик", "получатель", "отправитель"]
                    .iter()
                    .any(|w| window.contains(w));
                if has_context {
                    push_fio(doc, out, t.start, t.end, 0.75);
                }
            }

            i += 1;
        }
    }
}

/// Проверяет, что между двумя токенами только пробелы/запятые (смежные).
fn are_adjacent(doc: &Document<'_>, a: &Token, b: &Token) -> bool {
    if b.start < a.end {
        return false;
    }
    doc.norm[a.end..b.start]
        .chars()
        .all(|c| c == ' ' || c == ',')
}

fn push_fio(doc: &Document<'_>, out: &mut Vec<Candidate>, start: usize, end: usize, score: f32) {
    let span = doc.to_original(start, end);
    let mut cand = Candidate::new(
        PdType::new(PdType::FIO),
        span,
        score,
        DetectorSource::Dictionary { id: "fio".into() },
    );
    cand.signals |= SignalFlags::DICT_HIT;
    out.push(cand);
}