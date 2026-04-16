#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message;

/// A minimal protobuf message to test decode robustness.
/// We don't import sanchr-proto to avoid build complexity in the fuzz crate.
#[derive(Clone, PartialEq, Message)]
pub struct FuzzMessage {
    #[prost(string, tag = "1")]
    pub field1: String,
    #[prost(bytes = "vec", tag = "2")]
    pub field2: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub field3: u64,
    #[prost(message, optional, tag = "4")]
    pub nested: Option<Box<FuzzNested>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct FuzzNested {
    #[prost(string, tag = "1")]
    pub value: String,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub items: Vec<Vec<u8>>,
}

fuzz_target!(|data: &[u8]| {
    let _ = FuzzMessage::decode(data);
});
