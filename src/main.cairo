%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_secp.bigint import (
    uint256_to_bigint,
)
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.uint256 import Uint256, uint256_check

from src.secp256r1.signature import verify_secp256r1_signature



@view
func verify_secp256r1{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    hash_len: felt, hash: felt*, signature_len: felt, signature: felt*, pubkey_len: felt, pubkey: felt*) {
    let (x) = uint256_to_bigint(Uint256(low=pubkey[0], high=pubkey[1]));
    let (y) = uint256_to_bigint(Uint256(low=pubkey[2], high=pubkey[3]));
    // validate r,s
    let r_uint256 = Uint256(low=signature[0], high=signature[1]);
    uint256_check(r_uint256);
    let s_uint256 = Uint256(low=signature[2], high=signature[3]);
    uint256_check(s_uint256);
    let (r_bigint3) = uint256_to_bigint(r_uint256);
    let (s_bigint3) = uint256_to_bigint(s_uint256);
    let (hash_bigint3) = uint256_to_bigint(Uint256(low=hash[0], high=hash[1]));
    verify_secp256r1_signature(hash_bigint3, r_bigint3, s_bigint3, EcPoint(x=x, y=y));

    return ();

}
