use digest::Digest;
use num::BigUint;
use sha2::Sha256;
use crate::crypto::elgamal;
use crate::crypto::group::{Element, Exponent};

/// Specifies how the challenge should be computed by specifying which
/// inputs should be hashed, and in what order.
#[derive(Debug, Clone)]
pub struct Spec<'a, P>(pub &'a [Input<'a, P>]);

/// A single input to the hash function. It is parametrized over [P],
/// the type of information that can be provided by the proof, because
/// different proofs contain different pieces of information.
#[derive(Debug, Copy, Clone)]
pub enum Input<'a, P> {
    /// An input provided by the creator of the specification
    External(&'a BigUint),
    /// An input provided by the proof being checked
    Proof(P),
}

impl<'a, P: 'a + Copy> Spec<'a, P> {
    pub fn exec<R, D>(self, resolver: R) -> BigUint
    where
        R: 'a + Fn(P) -> &'a BigUint,
        D: Digest,
    {
        // TODO: pretty sure there should be some padding / length between elements?
        let hash = self
            .resolve(resolver)
            .map(BigUint::to_bytes_be)
            .fold(D::new(), D::chain)
            .result();

        BigUint::from_bytes_be(hash.as_slice())
    }

    fn resolve<R>(self, resolver: R) -> impl Iterator<Item = &'a BigUint> + 'a
    where
        R: 'a + Fn(P) -> &'a BigUint,
    {
        self.0.iter().copied().map(move |i| match i {
            Input::External(x) => x,
            Input::Proof(x) => resolver(x),
        })
    }
}

pub fn hash_uints(xs: &[&BigUint]) -> BigUint {
    let inputs = xs.iter().map(|i| Input::External(i)).collect::<Vec<_>>();
    Spec::<()>(&inputs).exec::<_, Sha256>(|_| unreachable!())
}

/// Hash together a BigUint, a message, and a commitment.
pub fn hash_umc(
    u: &BigUint,
    m: &elgamal::Message,
    c: &elgamal::Message,
) -> BigUint {
    hash_uints(&[
        u,
        m.public_key.as_uint(),
        m.ciphertext.as_uint(),
        c.public_key.as_uint(),
        c.ciphertext.as_uint(),
    ])
}

/// Hash together a BigUint, a message, and two commitments.
pub fn hash_umcc(
    u: &BigUint,
    m: &elgamal::Message,
    c1: &elgamal::Message,
    c2: &elgamal::Message,
) -> BigUint {
    hash_uints(&[
        u,
        m.public_key.as_uint(),
        m.ciphertext.as_uint(),
        c1.public_key.as_uint(),
        c1.ciphertext.as_uint(),
        c2.public_key.as_uint(),
        c2.ciphertext.as_uint(),
    ])
}

/// Hash together three BigUints.
pub fn hash_uuu(
    u1: &BigUint,
    u2: &BigUint,
    u3: &BigUint,
) -> BigUint {
    hash_uints(&[u1, u2, u3])
}

/// Hash together a BigUint and two group Elements.
pub fn hash_uee(
    u: &BigUint,
    e1: &Element,
    e2: &Element,
) -> BigUint {
    hash_uints(&[u, e1.as_uint(), e2.as_uint()])
}

