use lazy_static::*;
use num::traits::{Num, One, Pow, Zero};
use num::BigUint;
use serde::{Deserialize, Serialize};
use std::ops::{Add, Div, Mul, Neg, Sub};

// TODO: custom serde instances that reject things not in the group

/// An element of the multiplicative group of integers modulo some prime.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Element {
    #[serde(with = "crate::serialize::big_uint")]
    element: BigUint,
}

/// An exponent in the additive group of integers modulo some prime minus one.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Exponent {
    #[serde(with = "crate::serialize::big_uint")]
    exponent: BigUint,
}

/// A coefficient of the polynomial used to reconstruct missing trustee keys.  This is simply an
/// integer mod `p`.  Unlike `Element`, there is no requerement that it is non-zero.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Coefficient {
    #[serde(with = "crate::serialize::big_uint")]
    coefficient: BigUint,
}

impl Element {
    /// Return the generator element of the group `G`.
    pub fn gen() -> Element {
        Element::unchecked(GENERATOR.clone())
    }

    /// Inject an integer into the group: this wraps modulo the prime modulus if
    /// the number is greater than or equal to the modulus.
    pub fn new(element: BigUint) -> Element {
        Element::unchecked(element % &*PRIME_MODULUS)
    }

    /// Construct an element of a group without checking whether the given
    /// integer is part of the group: this is unsafe!
    fn unchecked(element: BigUint) -> Element {
        Element { element }
    }

    pub fn as_uint(&self) -> &BigUint {
        &self.element
    }
}

impl Exponent {
    /// Inject an integer into the exponential group: this wraps modulo the
    /// prime modulus if the number is greater than or equal to the modulus.
    pub fn new(exponent: BigUint) -> Exponent {
        Exponent::unchecked(exponent % &*PRIME_SUBGROUP_MODULUS)
    }

    /// Construct an exponent of a group without checking whether the given
    /// integer is part of the group: this is unsafe!
    fn unchecked(exponent: BigUint) -> Exponent {
        Exponent { exponent }
    }

    pub fn as_uint(&self) -> &BigUint {
        &self.exponent
    }
}

impl Coefficient {
    /// Inject an integer into the exponential group: this wraps modulo the
    /// prime modulus if the number is greater than or equal to the modulus.
    pub fn new(coefficient: BigUint) -> Coefficient {
        Coefficient::unchecked(coefficient % &*PRIME_SUBGROUP_MODULUS)
    }

    /// Construct an exponent of a group without checking whether the given
    /// integer is part of the group: this is unsafe!
    fn unchecked(coefficient: BigUint) -> Coefficient {
        Coefficient { coefficient }
    }

    pub fn as_uint(&self) -> &BigUint {
        &self.coefficient
    }

    pub fn to_element(&self) -> Element {
        Element::new(self.coefficient.clone())
    }

    pub fn to_exponent(&self) -> Exponent {
        Exponent::new(self.coefficient.clone())
    }

    pub fn from_element(e: Element) -> Self {
        Self::unchecked(e.as_uint().clone())
    }

    pub fn from_exponent(e: Exponent) -> Self {
        Self::unchecked(e.as_uint().clone())
    }
}

lazy_static! {
    static ref GENERATOR_ELEMENT: Element = Element::gen();
}

pub fn generator() -> &'static Element {
    &*GENERATOR_ELEMENT
}

pub fn prime() -> &'static BigUint {
    &*PRIME_MODULUS
}

pub fn prime_minus_one() -> &'static BigUint {
    &*PRIME_MODULUS_MINUS_ONE
}
pub fn subgroup_prime() -> &'static BigUint {
    &*PRIME_SUBGROUP_MODULUS
}

// Multiplicative group operations

impl One for Element {
    /// Return the element one, which is always part of any valid group.
    fn one() -> Element {
        Element::unchecked(BigUint::one())
    }
}

impl Element {
    /// Take the multiplicative inverse of the element.
    pub fn inverse(&self) -> Element {
        // https://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Using_Euler's_theorem
        // "In the special case where m is a prime, ϕ(m) = m-1, and a modular
        // inverse is given by a^-1 = a^(m-2) (mod m)."
        Element::unchecked(
            self.element
                .modpow(&(&*PRIME_MODULUS - 2_u8), &*PRIME_MODULUS),
        )
    }
}

impl Mul for Element {
    type Output = Element;
    /// Multiply group elements, modulo the group's prime modulus.
    fn mul(self, other: Element) -> Element {
        Element::unchecked(self.element * other.element % &*PRIME_MODULUS)
    }
}

impl Mul for &Element {
    type Output = Element;
    /// Multiply group elements, modulo the group's prime modulus.
    fn mul(self, other: &Element) -> Element {
        Element::unchecked(&self.element * &other.element % &*PRIME_MODULUS)
    }
}

impl Div for Element {
    type Output = Element;
    /// Divide a group element by another group element.
    fn div(self, other: Element) -> Element {
        self * other.inverse()
    }
}

impl Div for &Element {
    type Output = Element;
    /// Divide a group element by another group element.
    fn div(self, other: &Element) -> Element {
        self * &other.inverse()
    }
}

impl Pow<&Exponent> for &Element {
    type Output = Element;
    /// Raise one group element to the power of an element of the corresponding
    /// exponential group, modulo the group's prime modulus.
    fn pow(self, other: &Exponent) -> Element {
        Element::unchecked(self.element.modpow(&other.exponent, &*PRIME_MODULUS))
    }
}

impl Pow<&BigUint> for &Element {
    type Output = Element;
    /// Raise a group element to an arbitrary exponent.
    fn pow(self, other: &BigUint) -> Element {
        Element::unchecked(self.element.modpow(other, &*PRIME_MODULUS))
    }
}

pub fn gen_pow(exp: &Exponent) -> Element {
    Element::gen().pow(exp)
}

// Additive exponential group operations

impl Zero for Exponent {
    /// The zero exponent
    fn zero() -> Exponent {
        Exponent::unchecked(BigUint::zero())
    }
    /// Test if an exponent is zero
    fn is_zero(&self) -> bool {
        self.exponent.is_zero()
    }
}

impl One for Exponent {
    /// The one exponent
    fn one() -> Exponent {
        Exponent::unchecked(BigUint::one())
    }
    /// Test if an exponent is one
    fn is_one(&self) -> bool {
        self.exponent.is_one()
    }
}

impl Add for Exponent {
    type Output = Exponent;
    /// Add group exponents, modulo the group's prime modulus *minus one*.
    fn add(self, other: Exponent) -> Exponent {
        let a = self.exponent;
        let b = other.exponent;
        Exponent::unchecked((a + b) % &*PRIME_SUBGROUP_MODULUS)
    }
}

impl Add for &Exponent {
    type Output = Exponent;
    /// Add group exponents, modulo the group's prime modulus *minus one*.
    fn add(self, other: &Exponent) -> Exponent {
        let a = &self.exponent;
        let b = &other.exponent;
        Exponent::unchecked((a + b) % &*PRIME_SUBGROUP_MODULUS)
    }
}

impl Sub for Exponent {
    type Output = Exponent;
    /// Subtract group exponents, modulo the group's prime modulus *minus one*.
    fn sub(self, other: Exponent) -> Exponent {
        let a = self.exponent;
        let b = other.exponent;
        Exponent::unchecked((a + &*PRIME_SUBGROUP_MODULUS - b) % &*PRIME_SUBGROUP_MODULUS)
    }
}

impl Sub for &Exponent {
    type Output = Exponent;
    /// Subtract group exponents, modulo the group's prime modulus *minus one*.
    fn sub(self, other: &Exponent) -> Exponent {
        let a = &self.exponent;
        let b = &other.exponent;
        Exponent::unchecked((a + &*PRIME_SUBGROUP_MODULUS - b) % &*PRIME_SUBGROUP_MODULUS)
    }
}

impl Mul for Exponent {
    type Output = Exponent;
    /// Multiply group exponents, modulo the group's prime modulus *minus one*.
    fn mul(self, other: Exponent) -> Exponent {
        let a = self.exponent;
        let b = other.exponent;
        Exponent::unchecked(a * b % &*PRIME_SUBGROUP_MODULUS)
    }
}

impl Mul for &Exponent {
    type Output = Exponent;
    /// Multiply group exponents, modulo the group's prime modulus *minus one*.
    fn mul(self, other: &Exponent) -> Exponent {
        let a = &self.exponent;
        let b = &other.exponent;
        Exponent::unchecked(a * b % &*PRIME_SUBGROUP_MODULUS)
    }
}

impl Neg for Exponent {
    type Output = Exponent;
    /// Negate an element of the exponential group.
    fn neg(self) -> Exponent {
        if self.exponent.is_zero() {
            self
        } else {
            Exponent::unchecked(&*PRIME_SUBGROUP_MODULUS - self.exponent)
        }
    }
}

impl Neg for &Exponent {
    type Output = Exponent;
    /// Negate an element of the exponential group.
    fn neg(self) -> Exponent {
        if self.exponent.is_zero() {
            self.clone()
        } else {
            Exponent::unchecked(&*PRIME_SUBGROUP_MODULUS - &self.exponent)
        }
    }
}

impl Pow<&BigUint> for &Exponent {
    type Output = Exponent;
    /// Raise a group element to an arbitrary exponent.
    fn pow(self, other: &BigUint) -> Exponent {
        Exponent::unchecked(self.exponent.modpow(other, &*PRIME_SUBGROUP_MODULUS))
    }
}

// Generic arithmetic mod `p`

impl Zero for Coefficient {
    fn zero() -> Coefficient {
        Coefficient::unchecked(BigUint::zero())
    }
    fn is_zero(&self) -> bool {
        self.coefficient.is_zero()
    }
}

impl One for Coefficient {
    fn one() -> Coefficient {
        Coefficient::unchecked(BigUint::one())
    }
    fn is_one(&self) -> bool {
        self.coefficient.is_one()
    }
}

impl Coefficient {
    pub fn inverse(&self) -> Coefficient {
        // https://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Using_Euler's_theorem
        // "In the special case where m is a prime, ϕ(m) = m-1, and a modular
        // inverse is given by a^-1 = a^(m-2) (mod m)."
        Coefficient::unchecked(
            self.coefficient
                .modpow(&(&*PRIME_SUBGROUP_MODULUS - 2_u8), &*PRIME_SUBGROUP_MODULUS),
        )
    }
}

impl Add for Coefficient {
    type Output = Coefficient;
    /// Add group coefficients, modulo the group's prime modulus *minus one*.
    fn add(self, other: Coefficient) -> Coefficient {
        let a = self.coefficient;
        let b = other.coefficient;
        Coefficient::unchecked((a + b) % &*PRIME_SUBGROUP_MODULUS)
    }
}

impl Add for &Coefficient {
    type Output = Coefficient;
    /// Add group coefficients, modulo the group's prime modulus *minus one*.
    fn add(self, other: &Coefficient) -> Coefficient {
        let a = &self.coefficient;
        let b = &other.coefficient;
        Coefficient::unchecked((a + b) % &*PRIME_SUBGROUP_MODULUS)
    }
}

impl Sub for Coefficient {
    type Output = Coefficient;
    /// Subtract group coefficients, modulo the group's prime modulus *minus one*.
    fn sub(self, other: Coefficient) -> Coefficient {
        let a = self.coefficient;
        let b = other.coefficient;
        Coefficient::unchecked((a + &*PRIME_SUBGROUP_MODULUS - b) % &*PRIME_SUBGROUP_MODULUS)
    }
}

impl Sub for &Coefficient {
    type Output = Coefficient;
    /// Subtract group coefficients, modulo the group's prime modulus *minus one*.
    fn sub(self, other: &Coefficient) -> Coefficient {
        let a = &self.coefficient;
        let b = &other.coefficient;
        Coefficient::unchecked((a + &*PRIME_SUBGROUP_MODULUS - b) % &*PRIME_SUBGROUP_MODULUS)
    }
}

impl Neg for Coefficient {
    type Output = Coefficient;
    /// Negate an element of the coefficiential group.
    fn neg(self) -> Coefficient {
        if self.coefficient.is_zero() {
            self
        } else {
            Coefficient::unchecked(&*PRIME_SUBGROUP_MODULUS - self.coefficient)
        }
    }
}

impl Neg for &Coefficient {
    type Output = Coefficient;
    /// Negate an element of the coefficiential group.
    fn neg(self) -> Coefficient {
        if self.coefficient.is_zero() {
            self.clone()
        } else {
            Coefficient::unchecked(&*PRIME_SUBGROUP_MODULUS - &self.coefficient)
        }
    }
}

impl Mul for Coefficient {
    type Output = Coefficient;
    fn mul(self, other: Coefficient) -> Coefficient {
        Coefficient::unchecked(self.coefficient * other.coefficient % &*PRIME_SUBGROUP_MODULUS)
    }
}

impl Mul for &Coefficient {
    type Output = Coefficient;
    fn mul(self, other: &Coefficient) -> Coefficient {
        Coefficient::unchecked(&self.coefficient * &other.coefficient % &*PRIME_SUBGROUP_MODULUS)
    }
}

impl Div for Coefficient {
    type Output = Coefficient;
    fn div(self, other: Coefficient) -> Coefficient {
        self * other.inverse()
    }
}

impl Div for &Coefficient {
    type Output = Coefficient;
    fn div(self, other: &Coefficient) -> Coefficient {
        self * &other.inverse()
    }
}

impl Pow<&Exponent> for &Coefficient {
    type Output = Coefficient;
    fn pow(self, other: &Exponent) -> Coefficient {
        Coefficient::unchecked(
            self.coefficient
                .modpow(&other.exponent, &*PRIME_SUBGROUP_MODULUS),
        )
    }
}

impl Pow<&BigUint> for &Coefficient {
    type Output = Coefficient;
    fn pow(self, other: &BigUint) -> Coefficient {
        Coefficient::unchecked(self.coefficient.modpow(other, &*PRIME_SUBGROUP_MODULUS))
    }
}

// BigUint -> Element/Exponent conversion

/// Conversion from a number into a group element (via `TryFrom`) can fail if
/// the given element is too large for the group.
pub enum GroupError {
    TooLarge {
        /// The element in question which was too large
        number: BigUint,
        /// The modulus of the group
        modulus: &'static BigUint,
    },
}

impl From<BigUint> for Element {
    /// This succeeds if and only if the given value is strictly less than the
    /// prime modulus of the group.
    fn from(number: BigUint) -> Self {
        if !number.is_zero() && number < *PRIME_MODULUS {
            Element { element: number }
        } else {
            panic!("argument out of range for conversion to group element")
        }
    }
}

impl From<BigUint> for Exponent {
    /// This succeeds if and only if the given value is strictly less than the
    /// prime modulus of the group *minus one*.
    fn from(number: BigUint) -> Self {
        if number < *PRIME_SUBGROUP_MODULUS {
            Exponent { exponent: number }
        } else {
            panic!("argument out of range for conversion to group exponent")
        }
    }
}

impl From<BigUint> for Coefficient {
    fn from(number: BigUint) -> Self {
        if number < *PRIME_SUBGROUP_MODULUS {
            Coefficient {
                coefficient: number,
            }
        } else {
            panic!("argument out of range for conversion to coefficient")
        }
    }
}

impl From<u32> for Element {
    /// This succeeds if and only if the given value is strictly less than the
    /// prime modulus of the group.
    fn from(number: u32) -> Self {
        BigUint::from(number).into()
    }
}

impl From<u32> for Exponent {
    /// This succeeds if and only if the given value is strictly less than the
    /// prime modulus of the group *minus one*.
    fn from(number: u32) -> Self {
        BigUint::from(number).into()
    }
}

impl From<u32> for Coefficient {
    fn from(number: u32) -> Self {
        BigUint::from(number).into()
    }
}

// # The groups defined in [IETF RFC 3526](https://tools.ietf.org/html/rfc3526)

#[cfg(not(test))]
lazy_static! {
    /// The selected "safe" `PRIME_MODULUS` for all group operations
    pub static ref PRIME_MODULUS: BigUint =
        PRIME_1536.clone();

    pub static ref GENERATOR: BigUint = BigUint::from(4_u32);
}

#[cfg(test)]
lazy_static! {
    pub static ref PRIME_MODULUS: BigUint = BigUint::from(200087_u32);
    pub static ref GENERATOR: BigUint = BigUint::from(25_u32);
}

lazy_static! {
    static ref PRIME_1536: BigUint =
        parse_biguint_hex_or_panic(PRIME_HEX_1536);

    static ref PRIME_2048: BigUint =
        parse_biguint_hex_or_panic(PRIME_HEX_2048);

    static ref PRIME_3072: BigUint =
        parse_biguint_hex_or_panic(PRIME_HEX_3072);

    static ref PRIME_4096: BigUint =
        parse_biguint_hex_or_panic(PRIME_HEX_4096);

    static ref PRIME_6144: BigUint =
        parse_biguint_hex_or_panic(PRIME_HEX_6144);

    static ref PRIME_8192: BigUint =
        parse_biguint_hex_or_panic(PRIME_HEX_8192);

    /// The selected `PRIME_MODULUS` minus one (the modulus for the additive
    /// group of exponents)
    pub static ref PRIME_MODULUS_MINUS_ONE: BigUint =
        &*PRIME_MODULUS - BigUint::one();

    pub static ref PRIME_SUBGROUP_MODULUS: BigUint =
        (&*PRIME_MODULUS - BigUint::one()) / BigUint::from(2_u8);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn all_primes_parse() {
        assert!(*PRIME_1536 > BigUint::zero(), "MODP 1536 did not parse");
        assert!(*PRIME_2048 > BigUint::zero(), "MODP 2048 did not parse");
        assert!(*PRIME_3072 > BigUint::zero(), "MODP 3072 did not parse");
        assert!(*PRIME_4096 > BigUint::zero(), "MODP 4096 did not parse");
        assert!(*PRIME_6144 > BigUint::zero(), "MODP 6144 did not parse");
        assert!(*PRIME_8192 > BigUint::zero(), "MODP 8192 did not parse");
    }

    #[test]
    fn prime_modulus_minus_one_correct() {
        assert!(
            &*PRIME_MODULUS - BigUint::one() == *PRIME_MODULUS_MINUS_ONE,
            "PRIME_MODULUS - 1 != PRIME_MODULUS_MINUS_ONE"
        );
    }
}

/// Parse a hex string (which might contain spaces, tabs, or newlines) into a
/// BigUint or panic if it can't be done (this is meant to be used for
/// hard-coded constants)
fn parse_biguint_hex_or_panic(hex: &str) -> BigUint {
    BigUint::from_str_radix(
        &hex.replace(" ", "").replace("\n", "").replace("\t", ""),
        16,
    )
    .expect("Invalid hex input for parse_biguint_hex_or_panic")
}

/// The prime modulus for the 1536-bit group
const PRIME_HEX_1536: &str = "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
     29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
     EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
     E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
     EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
     C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
     83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
     670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF";

/// The prime modulus for the 2048-bit group
const PRIME_HEX_2048: &str = "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
     29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
     EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
     E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
     EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
     C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
     83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
     670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
     E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
     DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
     15728E5A 8AACAA68 FFFFFFFF FFFFFFFF";

/// The prime modulus for the 3072-bit group
const PRIME_HEX_3072: &str = "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
     29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
     EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
     E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
     EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
     C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
     83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
     670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
     E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
     DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
     15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
     ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
     ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
     F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
     BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
     43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF";

/// The prime modulus for the 4096-bit group
const PRIME_HEX_4096: &str = "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
     29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
     EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
     E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
     EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
     C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
     83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
     670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
     E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
     DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
     15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
     ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
     ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
     F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
     BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
     43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
     88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
     2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
     287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
     1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
     93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
     FFFFFFFF FFFFFFFF";

/// The prime modulus for the 6144-bit group
const PRIME_HEX_6144: &str = "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
     8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
     302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
     A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
     49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
     FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
     670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
     180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
     3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
     04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
     B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
     1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
     BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
     E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
     99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
     04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
     233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
     D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
     36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406
     AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918
     DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151
     2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03
     F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F
     BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
     CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B
     B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632
     387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E
     6DCC4024 FFFFFFFF FFFFFFFF";

/// The prime modulus for the 8192-bit group
const PRIME_HEX_8192: &str = "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
     29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
     EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
     E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
     EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
     C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
     83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
     670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
     E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
     DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
     15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
     ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
     ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
     F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
     BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
     43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
     88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
     2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
     287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
     1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
     93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
     36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD
     F8FF9406 AD9E530E E5DB382F 413001AE B06A53ED 9027D831
     179727B0 865A8918 DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B
     DB7F1447 E6CC254B 33205151 2BD7AF42 6FB8F401 378CD2BF
     5983CA01 C64B92EC F032EA15 D1721D03 F482D7CE 6E74FEF6
     D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F BEC7E8F3
     23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
     CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328
     06A1D58B B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C
     DA56C9EC 2EF29632 387FE8D7 6E3C0468 043E8F66 3F4860EE
     12BF2D5B 0B7474D6 E694F91E 6DBE1159 74A3926F 12FEE5E4
     38777CB6 A932DF8C D8BEC4D0 73B931BA 3BC832B6 8D9DD300
     741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C 5AE4F568
     3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9
     22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B
     4BCBC886 2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A
     062B3CF5 B3A278A6 6D2A13F8 3F44F82D DF310EE0 74AB6A36
     4597E899 A0255DC1 64F31CC5 0846851D F9AB4819 5DED7EA1
     B1D510BD 7EE74D73 FAF36BC3 1ECFA268 359046F4 EB879F92
     4009438B 481C6CD7 889A002E D5EE382B C9190DA6 FC026E47
     9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71
     60C980DD 98EDD3DF FFFFFFFF FFFFFFFF";
