use num::BigUint;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Group {
    /// The generator `g` of the multiplicative subgroup `Z^*_q`,
    /// where `p = 2q + 1`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    pub generator: BigUint,

    /// The safe prime modulus `p`
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    pub prime: BigUint,
}

/// An ElGamal message `(c, d)` encoding zero. This is useful because
/// you can only combine two ciphertexts if they both encode zero, as
/// in the equation `hᵘ = hᵗ⁺ᶜʳ = hᵗ (hʳ)ᶜ = d bᶜ`. This acts as a
/// committment to the one-time private key `t` used in this proof.
///
/// A message that has been encrypted using exponential ElGamal.
///
/// The encrypted message of the selection (the one or zero).
#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    /// The one-time public key `a = gʳ`, where `r` is the randomly
    /// generated one-time public key.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    pub public_key: BigUint,

    /// The encoding `b = gᵐ hʳ`, where `m` is the cleartext and `h`
    /// is the recipient public key being used for encryption.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    pub ciphertext: BigUint,
}


#[cfg(test)]
pub mod test {
    use num::BigUint;
    use super::*;

    pub fn group() -> Group {
        /*
        let mut p_bytes = Vec::new();
        let p_hex = b"
            FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
            020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
            4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
            EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05
            98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB
            9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
            E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
            3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D 04507A33
            A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
            ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B F12FFA06 D98A0864
            D8760273 3EC86A64 521F2B18 177B200C BBE11757 7A615D6C 770988C0 BAD946E2
            08E24FA0 74E5AB31 43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
            88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8
            DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
            233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
            93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199 FFFFFFFF FFFFFFFF
        " as &[u8];

        for &b in p_hex {
            if (b'0' <= b && b <= b'9') {
                p_bytes.push(b - b'0');
            } else if (b'A' <= b && b <= b'F') {
                p_bytes.push(b - b'A' + 10);
            }
        }
        */

        // Use a small prime for tests so they run quickly.  As long as all the one-time secrets
        // used in tests are less than 100000 (and thus less than p - 1), everything should work.
        Group {
            generator: 5_u32.into(),
            prime: 100103_u32.into(),
        }
    }

    pub fn private_key() -> BigUint {
        2546_u32.into()
    }

    pub fn public_key() -> BigUint {
        let Group { generator: g, prime: p } = group();
        let s = private_key();
        g.modpow(&s, &p)
    }

    pub fn extended_base_hash() -> BigUint {
        31268_u32.into()
    }
}
