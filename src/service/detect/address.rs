//! Детектор адреса (ADDRESS) — составной, из компонентов.

use regex::Regex;

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, DetectorSource, SignalFlags};
use crate::domain::pd_type::PdType;
use crate::domain::traits::{DetectCtx, Detector};

use super::context::{has_any_word, has_word, is_boundary, window};

pub struct AddressDetector {
    re_index: Regex,
    re_region: Regex,
    re_city: Regex,
    re_street: Regex,
    re_house: Regex,
    re_flat: Regex,
    types: Vec<PdType>,
}

impl Default for AddressDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressDetector {
    pub fn new() -> Self {
        Self {
            re_index: Regex::new(r"\d{6}").unwrap(),
            // Сокращения обязаны заканчиваться точкой, полные слова — границей слова.
            // Иначе «пер» ловится внутри «первого», «ао» внутри «хаос», и текст
            // «тридцать первого декабря» маскируется как улица.
            re_region: Regex::new(r"(\w+\s+)?\b(обл(асть|\.)|край|респ(ублика|\.)|ао|автономный округ)\b|\bреспублика \w+").unwrap(),
            re_city: Regex::new(r"(г\.|пгт\.?|пос\.|с\.|дер\.|\b(?:город|поселок|село|деревня)\b)\s*[\w-]+(\s[\w-]+)?").unwrap(),
            re_street: Regex::new(r"((?:ул|пр|пер|ш|наб|пл|мкр|бул|б-р|пр-т)\.|\b(?:ул|улица|проспект|переулок|шоссе|бульвар|набережная|площадь|проезд|тупик|микрорайон|пр-т|б-р)\b)\s*[\w\-. ]{1,40}").unwrap(),
            re_house: Regex::new(r"(д\.|дом)\s*\d+[а-я]?(\/\d+)?|(корп\.?|корпус|к\.)\s*\d+|(стр\.?|строение)\s*\d+").unwrap(),
            re_flat: Regex::new(r"(кв\.?|квартира|оф\.?|офис|комн\.?)\s*\d+").unwrap(),
            types: vec![
                PdType::new(PdType::ADDRESS),
                PdType::new(PdType::ADDR_INDEX),
                PdType::new(PdType::ADDR_REGION),
                PdType::new(PdType::ADDR_CITY),
                PdType::new(PdType::ADDR_STREET),
                PdType::new(PdType::ADDR_HOUSE),
                PdType::new(PdType::ADDR_FLAT),
            ],
        }
    }
}

impl Detector for AddressDetector {
    fn id(&self) -> &str {
        "address"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        let mut components: Vec<Candidate> = Vec::new();

        // Индекс
        for m in self.re_index.find_iter(&doc.norm) {
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            let first = doc.norm.as_bytes()[m.start()] - b'0';
            if !(1..=6).contains(&first) {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            let window = window(doc, m.start().saturating_sub(60), m.end() + 20);
            let has_context = has_word(window, "индекс");
            if has_context {
                let mut c = Candidate::new(
                    PdType::new(PdType::ADDR_INDEX),
                    span,
                    0.8,
                    DetectorSource::Regex { id: "address".into() },
                );
                c.signals |= SignalFlags::CONTEXT_POS;
                components.push(c);
            }
        }

        // Регион
        for m in self.re_region.find_iter(&doc.norm) {
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            components.push(Candidate::new(
                PdType::new(PdType::ADDR_REGION),
                span,
                0.7,
                DetectorSource::Regex { id: "address".into() },
            ));
        }

        // Город
        for m in self.re_city.find_iter(&doc.norm) {
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            components.push(Candidate::new(
                PdType::new(PdType::ADDR_CITY),
                span,
                0.7,
                DetectorSource::Regex { id: "address".into() },
            ));
        }

        // Улица: захватываем маркер + название, обрезаем до запятой/дома/конца.
        for caps in self.re_street.captures_iter(&doc.norm) {
            let m = caps.get(0).unwrap();
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            // Обрезаем название улицы до запятой, точки с запятой или маркера дома.
            let mut end = m.end();
            let rest = &doc.norm[m.end()..];
            if let Some(rel) = rest.find([',', ';']) {
                end = m.end() + rel;
            } else if let Some(rel) = rest.find(" д.") {
                end = m.end() + rel;
            } else if let Some(rel) = rest.find(" дом") {
                end = m.end() + rel;
            }
            // Убираем хвостовые пробелы.
            while end > m.start() && doc.norm.as_bytes()[end - 1] == b' ' {
                end -= 1;
            }
            if end <= m.start() {
                continue;
            }
            let span = doc.to_original(m.start(), end);
            components.push(Candidate::new(
                PdType::new(PdType::ADDR_STREET),
                span,
                0.7,
                DetectorSource::Regex { id: "address".into() },
            ));
        }

        // Дом
        for m in self.re_house.find_iter(&doc.norm) {
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            components.push(Candidate::new(
                PdType::new(PdType::ADDR_HOUSE),
                span,
                0.7,
                DetectorSource::Regex { id: "address".into() },
            ));
        }

        // Квартира
        for m in self.re_flat.find_iter(&doc.norm) {
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            components.push(Candidate::new(
                PdType::new(PdType::ADDR_FLAT),
                span,
                0.7,
                DetectorSource::Regex { id: "address".into() },
            ));
        }

        // Сортировка по start.
        components.sort_by_key(|c| c.span.start);

        // Сборка цепочек: соседние (разрыв ≤ 3 символа из , ; и пробелов) склеиваются.
        let mut chains: Vec<Vec<Candidate>> = Vec::new();
        for comp in components {
            if let Some(last) = chains.last_mut() {
                let last_end = last.last().unwrap().span.end;
                // Защита от перекрытия/непорядка (start > end → паника).
                if comp.span.start >= last_end {
                    let gap = &doc.original[last_end..comp.span.start];
                    let gap_clean = gap.chars().all(|c| c == ',' || c == ';' || c.is_whitespace());
                    if gap_clean && comp.span.start - last_end <= 3 {
                        last.push(comp);
                        continue;
                    }
                }
            }
            chains.push(vec![comp]);
        }

        // Публикуем компоненты как самостоятельные сущности (для mode: components).
        for chain in &chains {
            for comp in chain {
                out.push(comp.clone());
            }
        }

        for chain in chains {
            let has_street = chain.iter().any(|c| c.pd_type.as_str() == PdType::ADDR_STREET);
            let has_house = chain.iter().any(|c| c.pd_type.as_str() == PdType::ADDR_HOUSE);
            let has_city = chain.iter().any(|c| c.pd_type.as_str() == PdType::ADDR_CITY);

            let score = if chain.len() >= 3 && has_street && has_house {
                0.95
            } else if chain.len() == 2 && has_street && (has_city || has_house) {
                0.8
            } else {
                continue;
            };

            let start = chain.first().unwrap().span.start;
            let end = chain.last().unwrap().span.end;
            let span = crate::domain::document::Span::new(start, end);

            // Контекст ищем рядом с цепочкой, а не по всему документу: скан всего
            // текста на каждую найденную цепочку давал квадратичную сложность
            // (на 450 КБ это 4.6 с из 4.7 с всей детекции) и заодно поднимал score
            // любому адресу, если слово «адрес» встречалось где угодно в тексте.
            let ctx = original_window(doc.original, start, end, 120, 40);
            let has_addr_context = has_any_word(
                &ctx,
                &["проживает", "зарегистрирован", "адрес", "прописан"],
            );
            let score = if has_addr_context { (score + 0.2_f32).min(1.0_f32) } else { score };

            let mut cand = Candidate::new(
                PdType::new(PdType::ADDRESS),
                span,
                score,
                DetectorSource::Regex { id: "address".into() },
            );
            cand.components = chain;
            out.push(cand);
        }
    }
}
/// Окрестность диапазона в исходном тексте, приведённая к нижнему регистру.
/// Границы выравниваются по символам UTF-8.
fn original_window(text: &str, start: usize, end: usize, left: usize, right: usize) -> String {
    let mut lo = start.saturating_sub(left);
    let mut hi = (end + right).min(text.len());
    while lo > 0 && !text.is_char_boundary(lo) {
        lo -= 1;
    }
    while hi < text.len() && !text.is_char_boundary(hi) {
        hi += 1;
    }
    text[lo..hi].to_lowercase()
}
