//! Бенчмарки детекции.

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_detection(c: &mut Criterion) {
    c.bench_function("detect_1kb", |b| {
        b.iter(|| {
            let text = "Клиент Иванов Иван Иванович, паспорт 4509 123456, телефон +7 912 345-67-89, email ivanov@mail.ru, карта 4532 0151 1283 0366";
            let doc = pd_guard::domain::document::Document::new(text);
            let _ = doc.norm.len();
        });
    });
}

criterion_group!(benches, bench_detection);
criterion_main!(benches);