pub type Hash = [u8; 32];

#[macro_export]
macro_rules! hash_all {
    ( $( $x:expr ),* ) => {
        {
            let mut hasher: sha2::Sha256 = digest::Digest::new();
            $(
                let bytes: &[u8] = &*$x;
                hasher = digest::Digest::chain(hasher, bytes);
            )*
            digest::Digest::result(hasher).into()
        }
    };
}
