//! Доменная модель и абстракции. Без зависимостей от слоёв controller/service/adapter.

pub mod document;
pub mod entity;
pub mod errors;
pub mod pd_type;
pub mod sensitive;
pub mod traits;

pub use document::{Document, Span};
pub use entity::{Candidate, Entity, MaskRecord, MaskState};
pub use errors::{NerError, UpstreamError, VaultError};
pub use pd_type::PdType;
pub use sensitive::Sensitive;