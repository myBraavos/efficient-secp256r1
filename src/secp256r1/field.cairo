from starkware.cairo.common.cairo_secp.bigint import BigInt3, UnreducedBigInt3, nondet_bigint3
from starkware.cairo.common.math import assert_nn_le, assert_250_bit, assert_le_felt

from src.secp256r1.constants import (
    BASE, P0, P1, P2, SECP_REM,
    s0,s1,s2,
    r0,r1,r2
)

// Adapt from starkware.cairo.common.math's assert_250_bit
func assert_165_bit{range_check_ptr}(value) {
    const UPPER_BOUND = 2 ** 165;
    const SHIFT = 2 ** 128;
    const HIGH_BOUND = UPPER_BOUND / SHIFT;

    let low = [range_check_ptr];
    let high = [range_check_ptr + 1];

    %{
        from starkware.cairo.common.math_utils import as_int

        # Correctness check.
        value = as_int(ids.value, PRIME) % PRIME
        assert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**250).'

        # Calculation for the assertion.
        ids.high, ids.low = divmod(ids.value, ids.SHIFT)
    %}

    assert [range_check_ptr + 2] = HIGH_BOUND - 1 - high;

    assert value = high * SHIFT + low;

    let range_check_ptr = range_check_ptr + 3;
    return ();
}

// Computes the multiplication of two big integers, given in BigInt3 representation, modulo the
// secp256r1 prime.
//
// Arguments:
//   x, y - the two BigInt3 to operate on.
//
// Returns:
//   x * y in an UnreducedBigInt3 representation (the returned limbs may be above 3 * BASE).
//
// This means that if unreduced_mul is called on the result of nondet_bigint3, or the difference
// between two such results, we have:
//   Soundness guarantee: the limbs are in the range ().
//   Completeness guarantee: the limbs are in the range ().
func unreduced_mul(a: BigInt3, b: BigInt3) -> (res_low: UnreducedBigInt3) {
    tempvar twice_d2 = a.d2*b.d2;
    tempvar d1d2 = a.d2*b.d1 + a.d1*b.d2;
    return (
        UnreducedBigInt3(
            d0=a.d0*b.d0 + s0*twice_d2 + r0*d1d2,
            d1=a.d1*b.d0 + a.d0*b.d1 + s1*twice_d2 + r1*d1d2,
            d2=a.d2*b.d0 + a.d1*b.d1 + a.d0*b.d2 + s2*twice_d2 + r2*d1d2,
        ),
    );
}

// Computes the square of a big integer, given in BigInt3 representation, modulo the
// secp256r1 prime.
//
// Has the same guarantees as in unreduced_mul(a, a).
func unreduced_sqr(a: BigInt3) -> (res_low: UnreducedBigInt3) {
    tempvar twice_d2 = a.d2*a.d2;
    tempvar twice_d1d2 = a.d2*a.d1 + a.d1*a.d2;
    tempvar d1d0 = a.d1*a.d0;
    return (
        UnreducedBigInt3(
            d0=a.d0*a.d0 + s0*twice_d2 + r0*twice_d1d2,
            d1=d1d0 + d1d0 + s1*twice_d2 + r1*twice_d1d2,
            d2=a.d2*a.d0 + a.d1*a.d1 + a.d0*a.d2 + s2*twice_d2 + r2*twice_d1d2,
        ),
    );
}

// Verifies that the given unreduced value is equal to zero modulo the secp256r1 prime.
//
// Completeness assumption: val's limbs are in the range (-2**210.99, 2**210.99).
// Soundness assumption: val's limbs are in the range (-2**250, 2**250).
func verify_zero{range_check_ptr}(val: UnreducedBigInt3) {
    alloc_locals;
    local q;
    local q_sign;
    %{ from starkware.cairo.common.cairo_secp.secp_utils import SECP256R1_P as SECP_P %}
    %{
        from starkware.cairo.common.cairo_secp.secp_utils import pack

        q, r = divmod(pack(ids.val, PRIME), SECP_P)
        assert r == 0, f"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}."
        if q >= 0:
            ids.q = q % PRIME
            ids.q_sign = 1
        else:
            ids.q = (0-q) % PRIME
            ids.q_sign = -1 % PRIME
    %}
    // assert_250_bit(q); // 256K steps
    // assert_le_felt(q, 2**165); // 275K steps
    assert_165_bit(q);
    assert q_sign*(val.d2 + val.d1/BASE + val.d0 / BASE**2) = q * ((BASE / 4) - SECP_REM / BASE ** 2);
    // Multiply by BASE**2 both sides:
    //  (q_sign) * val = q * (BASE**3 / 4 - SECP_REM)
    //            = q * (2**256 - SECP_REM) = q * secp256r1_prime = 0 mod secp256r1_prime
    return ();
}

// Returns 1 if x == 0 (mod secp256r1_prime), and 0 otherwise.
//
// Completeness assumption: x's limbs are in the range (-BASE, 2*BASE).
// Soundness assumption: x's limbs are in the range (-2**107.49, 2**107.49).
func is_zero{range_check_ptr}(x: BigInt3) -> (res: felt) {
    %{ from starkware.cairo.common.cairo_secp.secp_utils import SECP256R1_P as SECP_P %}
    %{
        from starkware.cairo.common.cairo_secp.secp_utils import pack
        x = pack(ids.x, PRIME) % SECP_P
    %}
    if (nondet %{ x == 0 %} != 0) {
        verify_zero(UnreducedBigInt3(d0=x.d0, d1=x.d1, d2=x.d2));
        return (res=1);
    }

    %{
        from starkware.python.math_utils import div_mod

        value = x_inv = div_mod(1, x, SECP_P)
    %}
    let (x_inv) = nondet_bigint3();
    let (x_x_inv) = unreduced_mul(x, x_inv);

    // Check that x * x_inv = 1 to verify that x != 0.
    verify_zero(UnreducedBigInt3(d0=x_x_inv.d0 - 1, d1=x_x_inv.d1, d2=x_x_inv.d2));
    return (res=0);
}
