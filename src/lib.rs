//! PD-Guard — сервис идентификации, маскирования и демаскирования ПД для LLM.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod config;
pub mod controller;
pub mod domain;
pub mod infra;
pub mod service;

pub use domain::*;