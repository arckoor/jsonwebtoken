use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

use crate::errors::Result;

#[inline]
pub(crate) fn b64_encode<T: AsRef<[u8]>>(input: T) -> String {
    Base64UrlUnpadded::encode_string(input.as_ref())
}

#[inline]
pub(crate) fn b64_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(input).map_err(|e| e.into())
}

#[inline]
pub(crate) fn b64_decode_ct<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>> {
    let mut input = input.as_ref().to_vec();
    let len = Base64::decode_in_place(&mut input)
        .map_err(<base64ct::InvalidEncodingError as Into<base64ct::Error>>::into)?
        .len();
    input.truncate(len);
    Ok(input)
}

pub(crate) fn b64_decode_urlsafe_ct<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>> {
    let mut input = input.as_ref().to_vec();
    let len = Base64UrlUnpadded::decode_in_place(&mut input)
        .map_err(<base64ct::InvalidEncodingError as Into<base64ct::Error>>::into)?
        .len();
    input.truncate(len);
    Ok(input)
}

/// Serializes a struct to JSON and encodes it in base64
pub(crate) fn b64_encode_part<T: Serialize>(input: &T) -> Result<String> {
    let json = serde_json::to_vec(input)?;
    Ok(b64_encode(json))
}

/// This is used to decode from base64 then deserialize from JSON to several structs:
/// - The user-provided struct
/// - The `ClaimsForValidation` struct from this crate to run validation on
pub(crate) struct DecodedJwtPartClaims {
    b64_decoded: Vec<u8>,
}

impl DecodedJwtPartClaims {
    pub fn from_jwt_part_claims(encoded_jwt_part_claims: impl AsRef<[u8]>) -> Result<Self> {
        Ok(Self { b64_decoded: b64_decode(encoded_jwt_part_claims)? })
    }

    pub fn deserialize<'a, T: Deserialize<'a>>(&'a self) -> Result<T> {
        Ok(serde_json::from_slice(&self.b64_decoded)?)
    }
}
