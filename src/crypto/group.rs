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
        parse_biguint_hex_or_panic(PRIME_HEX);
    /// The modulus of the prime-order subgroup (the modulus for the additive group of exponents)
    pub static ref PRIME_SUBGROUP_MODULUS: BigUint =
        parse_biguint_hex_or_panic(SUBGROUP_PRIME_HEX);
    pub static ref GENERATOR: BigUint =
        parse_biguint_hex_or_panic(GENERATOR_HEX);
}

#[cfg(test)]
lazy_static! {
    pub static ref PRIME_MODULUS: BigUint = BigUint::from(200087_u32);
    pub static ref PRIME_SUBGROUP_MODULUS: BigUint =
        (&*PRIME_MODULUS - BigUint::one()) / BigUint::from(2_u8);
    pub static ref GENERATOR: BigUint = BigUint::from(25_u32);
}

lazy_static! {
    /// The selected `PRIME_MODULUS` minus one (used only for generating random group elements)
    pub static ref PRIME_MODULUS_MINUS_ONE: BigUint =
        &*PRIME_MODULUS - BigUint::one();
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn all_params_parse() {
        assert!(
            *PRIME_MODULUS > BigUint::zero(),
            "PRIME_MODULUS did not parse"
        );
        assert!(
            *PRIME_SUBGROUP_MODULUS > BigUint::zero(),
            "PRIME_SUBGROUP_MODULUS did not parse"
        );
        assert!(*GENERATOR > BigUint::zero(), "GENERATOR did not parse");
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

// Prime values below must match those used in the C API:
// https://github.com/microsoft/electionguard-c/blob/master/src/electionguard/bignum.c

/// Q - the prime modulus for the prime-order subgroup.  This is the largest 256-bit prime.
const SUBGROUP_PRIME_HEX: &str = "
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFF43
";

/// P - the prime modulus for the main group.  This is the largest 4096-bit prime that is one
/// greater than a multiple of Q.
const PRIME_HEX: &str = "
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFba
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FE0175E30B1B0E79
    1DB502994F24DFB1
";

/// G - the generator for the group
const GENERATOR_HEX: &str = "
    9B61C275E06F3E38 372F9A9ADE0CDC4C 82F4CE5337B3EF0E
    D28BEDBC01342EB8 9977C8116D741270 D45B0EBE12D96C5A
    EE997FEFDEA18569 018AFE1284E702BB 9B8C78E03E697F37
    8D25BCBCB94FEFD1 2B7F97047F634232 68881C3B96B389E1
    34CB3162CB73ED80 52F7946C7E72907F D8B96862D443B5C2
    6F7B0E3FDC9F035C BF0F5AAB670B7901 1A8BCDEBCF421CC9
    CBBE12C788E50328 041EB59D81079497 B667B96049DA04C7
    9D60F527B1C02F7E CBA66849179CB5CF BE7C990CD888B69C
    44171E4F54C21A8C FE9D821F195F7553 B73A705707263EAE
    A3B7AFA7DED79ACF 5A64F3BFB939B815 C52085F40714F4C6
    460B0B0C3598E317 46A06C2A3457676C B345C8A390EBB942
    8CEECEFA6FCB1C27 A9E527A6C55B8D6B 2B1868D6EC719E18
    9A799605C540F864 1F135D5DC7FB62D5 8E0DE0B6AE3AB90E
    91FB996505D7D928 3DA833FF0CB6CC8C A7BAFA0E90BB1ADB
    81545A801F0016DC 7088A4DF2CFB7D6D D876A2A5807BDAA4
    000DAFA2DFB6FBB0 ED9D775589156DDB FC24FF2203FFF9C5
    CF7C85C68F66DE94 C98331F50FEF59CF 8E7CE9D95FA008F7
    C1672D269C163751 012826C4C8F5B5F4 C11EDB62550F3CF9
    3D86F3CC6E22B0E7 69AC659157F40383 B5DF9DB9F8414F6C
    B5FA7D17BDDD3BC9 0DC7BDC39BAF3BE6 02A99E2A37CE3A5C
    098A8C1EFD3CD28A 6B79306CA2C20C55 174218A3935F697E
    813628D2D861BE54
";
