use num::BigUint;
use std::borrow::Cow;

pub type Hash = [u8; 32];

pub trait AsBytes {
    fn as_bytes(self: &Self) -> Cow<[u8]>;
}

impl<'b> AsBytes for Hash {
    fn as_bytes<'a>(self: &'a Self) -> Cow<[u8]> {
        Cow::Borrowed(self)
    }
}

impl AsBytes for BigUint {
    fn as_bytes(self: &Self) -> Cow<[u8]> {
        Cow::Owned(self.to_bytes_be())
    }
}

#[macro_export]
macro_rules! hash_all {
    ( $( $x:expr ),* ) => {
        {
            let mut hasher: sha2::Sha256 = digest::Digest::new();
            $(
                let bytes: std::borrow::Cow<[u8]> = crate::election::hash::AsBytes::as_bytes($x);
                hasher = digest::Digest::chain(hasher, bytes);
            )*
            digest::Digest::result(hasher).into()
        }
    };
}
