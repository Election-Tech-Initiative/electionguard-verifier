use num::BigUint;

/// Negation in the group with modulus `p`.
pub fn mod_neg(a: &BigUint, p: &BigUint) -> BigUint {
    (p - a % p) % p
}

/// Subtraction in the group with modulus `p`.
pub fn mod_sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    (a % p + p - b % p) % p
}

/// Multiplicative inversion (reciprocal) in the group with prime modulus `p`.
pub fn mod_inv(a: &BigUint, p: &BigUint) -> BigUint {
    // https://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Using_Euler's_theorem
    // "In the special case where m is a prime, ϕ(m) = m-1, and a modular inverse is given by
    // a^-1 = a^(m-2) (mod m)."
    a.modpow(&(p - 2_u8), p)
}

