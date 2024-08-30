use std::sync::Arc;
use hmac::digest::Digest;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroize;
use crate::ever::errors::Error;

pub mod hdkey;
pub mod errors;
pub mod boc;

#[derive(Debug, Clone)]
pub(crate) struct SecretBufConst<const N: usize>(pub [u8; N]);

// impl<const N: usize> Default for SecretBufConst<N> {
//     fn default() -> Self {
//         Self([0u8; N])
//     }
// }

impl<const N: usize> Drop for SecretBufConst<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> std::ops::Deref for SecretBufConst<N> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> std::ops::DerefMut for SecretBufConst<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBufConst<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for SecretBufConst<N> {
    fn from(data: [u8; N]) -> Self {
        Self(data)
    }
}

pub type ClientResult<T> = Result<T, ClientError>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ClientError {
    pub code: u32,
    pub message: String,
    pub data: Value,
}

impl ClientError {
    pub fn with_code_message(code: u32, message: String) -> Self {
        Self {
            code,
            message,
            data: json!({
                "core_version": "gate",
            }),
        }
    }

}
pub(crate) fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

static XPRV_VERSION: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];


impl<const N: usize> Default for SecretBufConst<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

pub(crate) type Key192 = SecretBufConst<24>;
pub(crate) type Key256 = SecretBufConst<32>;
pub(crate) type Key264 = SecretBufConst<33>;
pub(crate) type Key512 = SecretBufConst<64>;


pub(crate) fn key512(slice: &[u8]) -> ClientResult<Key512> {
    key_from_slice(slice)
}

pub(crate) fn key256(slice: &[u8]) -> ClientResult<Key256> {
    key_from_slice(slice)
}

pub(crate) fn key_from_slice<const N: usize>(slice: &[u8]) -> ClientResult<SecretBufConst<N>> {
    if slice.len() != N {
        return Err(ClientError {
            code: 0,
            message: "slice len() not correct".to_string(),
            data: Default::default(),
        });
    }
    let mut key = SecretBufConst([0u8; N]);
    key.0.copy_from_slice(slice);
    Ok(key)
}


///// 以下为账号编码
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AbiParam {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: String,
    #[serde(default)]
    pub components: Vec<AbiParam>,
    #[serde(default)]
    pub init: bool,
}

impl TryInto<ever_abi::Param> for AbiParam {
    type Error = ClientError;

    fn try_into(self) -> ClientResult<ever_abi::Param> {
        serde_json::from_value(
            serde_json::to_value(&self)
                .map_err(|err| Error::invalid_json(err))?
        ).map_err(|err| Error::invalid_json(err))
    }
}

