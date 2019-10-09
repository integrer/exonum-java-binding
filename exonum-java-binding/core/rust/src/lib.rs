// Copyright 2018 The Exonum Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Rust jni helpers for java bindings.
//!
//! All methods catch rust-panic and then rethrow java exception, but because of JNI-specific,
//! some default stub value still should be returned from the Rust side.

#![deny(missing_docs)]
// Function names must follow Java naming for the native functions.
#![allow(non_snake_case)]

extern crate chrono;
pub extern crate exonum;
extern crate exonum_cli;
#[macro_use]
extern crate exonum_derive;
extern crate exonum_testkit;
extern crate exonum_time;
extern crate failure;
extern crate futures;
pub extern crate jni;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate parking_lot;
extern crate protobuf;
extern crate serde;
#[macro_use]
extern crate serde_derive;
pub extern crate serde_json;
extern crate structopt;
#[cfg(test)]
extern crate tempfile;
extern crate toml;

pub use exonum::exonum_merkledb;
pub use jni::errors::{Error as JniError, ErrorKind as JniErrorKind, Result as JniResult};
pub use jni::Executor;

pub use handle::resource_manager::*;
pub use proxy::*;
pub use runtime::*;
pub use storage::*;
pub use testkit::*;

pub use self::handle::{cast_handle, drop_handle, Handle, to_handle};

pub mod handle;
mod proto;
mod proxy;
mod runtime;
mod storage;
mod testkit;
pub mod utils;

