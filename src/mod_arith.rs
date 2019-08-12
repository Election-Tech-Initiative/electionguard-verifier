use num::BigUint;
use std::ops::{
    Add, AddAssign, BitXor, BitXorAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign,
};

#[macro_use]
mod macros;

#[derive(Debug, Clone, PartialEq)]
pub struct Num {
    modulus: BigUint,
    val: BigUint,
}

// Implement the the trait and the assign trait for all combinations
// of owned and refs, forwarding everything to the owned assign
// implementation
impl_all_binop_assign!(impl Add, AddAssign for Num, add, add_assign);
impl_all_binop_assign!(impl Div, DivAssign for Num, div, div_assign);
impl_all_binop_assign!(impl Mul, MulAssign for Num, mul, mul_assign);

// Implement subtraction more manually so we can handle wrapping
// around zero
forward_all_binop_to_val_ref!(impl Sub for Num, sub);
forward_val_ref_binop_to_val_assign!(impl Sub for Num, sub, SubAssign, sub_assign);
forward_val_assign!(impl SubAssign for Num, sub_assign);

impl<'a> SubAssign<&'a Num> for Num {
    #[inline]
    fn sub_assign(&mut self, other: &Num) {
        check_moduli!(self, other);
        if self.val >= other.val {
            self.val -= &other.val;
            self.val %= &self.modulus;
        } else {
            self.val = &other.val - &self.val;
            self.val %= &self.modulus;
            self.val = &self.modulus - &self.val;
            self.val %= &self.modulus;
        }
    }
}

// Use the caret (BitXor) for modular exponentiation
forward_all_binop_to_val_ref!(impl BitXor for Num, bitxor);
forward_val_ref_binop_to_val_assign!(impl BitXor for Num, bitxor, BitXorAssign, bitxor_assign);
forward_val_assign!(impl BitXorAssign for Num, bitxor_assign);

impl<'a> BitXorAssign<&'a Num> for Num {
    #[inline]
    fn bitxor_assign(&mut self, other: &Num) {
        check_moduli!(self, other);
        self.val = BigUint::modpow(&self.val, &other.val, &self.modulus);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod no_overflow {
        use super::*;

        fn make_num(x: u32) -> Num {
            Num {
                modulus: From::from(5u8),
                val: From::from(x),
            }
        }

        #[test]
        fn test_add() -> () {
            assert_eq!(make_num(1) + make_num(3), make_num(4));
        }

        #[test]
        fn test_div() -> () {
            assert_eq!(make_num(3) / make_num(2), make_num(1));
        }

        #[test]
        fn test_mul() -> () {
            assert_eq!(make_num(2) * make_num(2), make_num(4));
        }

        #[test]
        fn test_sub() -> () {
            assert_eq!(make_num(3) - make_num(2), make_num(1));
        }

        #[test]
        fn test_pow() -> () {
            assert_eq!(make_num(2) ^ make_num(2), make_num(4));
        }
    }

    mod overflow {
        use super::*;

        fn make_num(x: u32) -> Num {
            Num {
                modulus: From::from(5u8),
                val: From::from(x),
            }
        }

        #[test]
        fn test_add() -> () {
            assert_eq!(make_num(7) + make_num(3), make_num(0));
        }

        #[test]
        fn test_div() -> () {
            assert_eq!(make_num(12) / make_num(2), make_num(1));
        }

        #[test]
        fn test_mul() -> () {
            assert_eq!(make_num(4) * make_num(3), make_num(2));
        }

        #[test]
        fn test_sub() -> () {
            assert_eq!(make_num(3) - make_num(24), make_num(4));
        }

        #[test]
        fn test_sub_zero() -> () {
            assert_eq!(make_num(3) - make_num(8), make_num(0));
        }

        #[test]
        fn test_pow() -> () {
            assert_eq!(make_num(3) ^ make_num(8), make_num(1));
        }
    }

    mod different_moduli {
        #![allow(unused_must_use)]

        use super::*;

        fn num_modulo(modulus: u32) -> Num {
            Num {
                modulus: From::from(modulus),
                val: From::from(1u8),
            }
        }

        #[test]
        #[should_panic(expected = "Moduli do not match: 5 != 7")]
        fn test_add() -> () {
            num_modulo(5) + num_modulo(7);
        }

        #[test]
        #[should_panic(expected = "Moduli do not match: 5 != 7")]
        fn test_div() -> () {
            num_modulo(5) / num_modulo(7);
        }

        #[test]
        #[should_panic(expected = "Moduli do not match: 5 != 7")]
        fn test_mul() -> () {
            num_modulo(5) * num_modulo(7);
        }

        #[test]
        #[should_panic(expected = "Moduli do not match: 5 != 7")]
        fn test_sub() -> () {
            num_modulo(5) - num_modulo(7);
        }

        #[test]
        #[should_panic(expected = "Moduli do not match: 5 != 7")]
        fn test_pow() -> () {
            num_modulo(5) ^ num_modulo(7);
        }
    }
}
