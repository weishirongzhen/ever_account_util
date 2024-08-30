use std::cell::Cell;
use ever_block::{BuilderData, Deserializable, Number5, Serializable, SliceData, StateInitLib, TickTock};
use crate::ever::ClientResult;
use crate::ever::errors::Error;


#[derive(Clone)]
pub enum DeserializedBoc {
    Cell(ever_block::Cell),
    Bytes(Vec<u8>),
}



pub fn serialize_cell_to_bytes(cell: &ever_block::Cell, name: &str) -> ClientResult<Vec<u8>> {
    ever_block::boc::write_boc(&cell)
        .map_err(|err| Error::serialization_error(err, name))
}

pub fn serialize_cell_to_base64(cell: &ever_block::Cell, name: &str) -> ClientResult<String> {
    Ok(base64::encode(&serialize_cell_to_bytes(cell, name)?))
}

pub fn deserialize_cell_from_base64(
    b64: &str,
    name: &str,
) -> ClientResult<(Vec<u8>, ever_block::Cell)> {
    let bytes = base64::decode(&b64)
        .map_err(|err| Error::invalid_boc(format!("error decode {} BOC base64: {}", name, err)))?;

    let cell = ever_block::boc::read_single_root_boc(&bytes).map_err(|err| {
        Error::invalid_boc(format!("{} BOC deserialization error: {}", name, err))
    })?;

    Ok((bytes, cell))
}

pub fn get_cell(name: &str, b64: &str) -> ClientResult<(Vec<u8>, ever_block::Cell)> {
    return deserialize_cell_from_base64(b64, name);
}

pub fn serialize_object_to_cell<S: Serializable>(
    object: &S,
    name: &str,
) -> ClientResult<ever_block::Cell> {
    Ok(object
        .serialize()
        .map_err(|err| Error::serialization_error(err, name))?)
}

