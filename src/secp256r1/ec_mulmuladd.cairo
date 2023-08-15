//*************************************************************************************/
///* Copyright (C) 2022 - Renaud Dubois - This file is part of Cairo_musig2 project   */
///* License: This software is licensed under a dual BSD and GPL v2 license.          */
///* See LICENSE file at the root folder of the project.                              */
///* FILE: multipoint.cairo                                                           */
///*                                                                                  */
///*                                                                                  */
///* DESCRIPTION: optimization of dual base multiplication                            */
///* the algorithm combines the so called Shamir's trick with Windowing method        */
//*************************************************************************************/
from starkware.cairo.common.cairo_secp.bigint import BigInt3

from src.secp256r1.ec import EcPoint, ec_add, ec_mul, ec_double


//Structure storing all aP+b.Q for (a,b) in [0..3]x[0..3]
struct Window {
    G: EcPoint,
    Q: EcPoint,
    W3: EcPoint,
    W4: EcPoint,
    W5: EcPoint,
    W6: EcPoint,
    W7: EcPoint,
    W8: EcPoint,
    W9: EcPoint,
    W10: EcPoint,
    W11: EcPoint,
    W12: EcPoint,
    W13: EcPoint,
    W14: EcPoint,
    W15: EcPoint,
}


//https://crypto.stackexchange.com/questions/99975/strauss-shamir-trick-on-ec-multiplication-by-scalar,
//* Internal call for recursion of point multiplication via Shamir's trick+Windowed method */
func ec_mulmuladd_W_inner{range_check_ptr}(
    R: EcPoint, Prec:Window,
    scalar_u: felt, scalar_v: felt, m: felt,
    computed_u: felt, computed_v: felt,
) -> (res: EcPoint, updated_u: felt, updated_v: felt) {
    alloc_locals;
    let mm2 = m-2;

    //(8*v1 4*u1+ 2*v0 + u0), where (u1,u0) represents two bit at index m of scalar u, (resp for v)
    local quad_bit;

    if (m == -1) {
        return (res=R, updated_u=computed_u, updated_v=computed_v);
    }

     //still have to make the last addition over 1 bit (initial length was odd)
    if(m == 0){
        let u0 = scalar_u - 2*computed_u;
        let v0 = scalar_v - 2*computed_v;
        let (double_point) = ec_double(R);

        if (u0 == 0 and v0 == 0) {
            return (res=double_point, updated_u=2*computed_u + 0, updated_v=2*computed_v + 0);
        }
        if (u0 == 1 and v0 == 0) {
            let (res) = ec_add(double_point,Prec.G);
            return (res=res, updated_u=2*computed_u + 1, updated_v=2*computed_v + 0);
        }
        if (u0 == 0 and v0 == 1) {
            let (res)=ec_add(double_point,Prec.Q);
            return (res=res, updated_u=2*computed_u + 0, updated_v=2*computed_v + 1);
        }

        assert u0 = 1;
        assert v0 = 1;
        let (res)=ec_add(double_point, Prec.W3);
        return (res=res, updated_u=2*computed_u + 1, updated_v=2*computed_v + 1);
    }

    let (double_point) = ec_double(R);
    let (quadruple_point) = ec_double(double_point);

    //compute quadruple (8*v1 + 4*u1 + 2*v0 + u0)
    %{
        ids.quad_bit = (
            8 * ((ids.scalar_v >> ids.m) & 1)
            + 4 * ((ids.scalar_u >> ids.m) & 1)
            + 2 * ((ids.scalar_v >> (ids.m - 1)) & 1)
            + ((ids.scalar_u >> (ids.m - 1)) & 1)
        )
    %}

    if (quad_bit == 0) {
        return ec_mulmuladd_W_inner(quadruple_point, Prec, scalar_u, scalar_v, mm2, 4*computed_u, 4*computed_v);
    }
    if (quad_bit == 1) {
        let (ecTemp) = ec_add(quadruple_point,Prec.G);
        return ec_mulmuladd_W_inner(ecTemp, Prec, scalar_u, scalar_v, mm2, 4*computed_u + 1, 4*computed_v);
    }
    if (quad_bit == 2) {
        let (ecTemp) = ec_add(quadruple_point,Prec.Q);
        return ec_mulmuladd_W_inner(ecTemp, Prec, scalar_u, scalar_v, mm2, 4*computed_u, 4*computed_v + 1);
    }
    if (quad_bit == 3) {
        let (ecTemp) = ec_add(quadruple_point,Prec.W3);
        return ec_mulmuladd_W_inner(ecTemp, Prec, scalar_u, scalar_v, mm2, 4*computed_u + 1, 4*computed_v + 1);
    }
    if (quad_bit == 4) {
        let (ecTemp) = ec_add(quadruple_point,Prec.W4);
        return ec_mulmuladd_W_inner(ecTemp, Prec, scalar_u, scalar_v, mm2, 4*computed_u + 2, 4*computed_v);
    }
    if (quad_bit == 5) {
        let (ecTemp) = ec_add(quadruple_point,Prec.W5);
        return ec_mulmuladd_W_inner(ecTemp, Prec, scalar_u, scalar_v, mm2, 4*computed_u + 3, 4*computed_v);
    }
    if (quad_bit == 6) {
        let (ecTemp) = ec_add(quadruple_point,Prec.W6);
        return ec_mulmuladd_W_inner(ecTemp, Prec, scalar_u, scalar_v, mm2, 4*computed_u + 2, 4*computed_v + 1);
    }
    if (quad_bit == 7) {
        let (ecTemp) = ec_add(quadruple_point,Prec.W7);
        return ec_mulmuladd_W_inner(ecTemp, Prec, scalar_u, scalar_v, mm2, 4*computed_u + 3, 4*computed_v + 1);
    }
    if (quad_bit == 8) {
        let (ecTemp) = ec_add(quadruple_point,Prec.W8);
        return ec_mulmuladd_W_inner(ecTemp, Prec, scalar_u, scalar_v, mm2, 4*computed_u, 4*computed_v + 2);
    }
    if (quad_bit == 9) {
        let (ecTemp) = ec_add(quadruple_point,Prec.W9);
        return ec_mulmuladd_W_inner(ecTemp, Prec, scalar_u, scalar_v, mm2, 4*computed_u + 1, 4*computed_v + 2);
    }
    if (quad_bit == 10) {
        let (ecTemp) = ec_add(quadruple_point,Prec.W10);
        return ec_mulmuladd_W_inner(ecTemp, Prec, scalar_u, scalar_v, mm2, 4*computed_u, 4*computed_v + 3);
    }
    if (quad_bit == 11) {
        let (ecTemp) = ec_add(quadruple_point,Prec.W11);
        return ec_mulmuladd_W_inner(ecTemp, Prec, scalar_u, scalar_v, mm2, 4*computed_u + 1, 4*computed_v + 3);
    }
    if (quad_bit == 12) {
        let (ecTemp) = ec_add(quadruple_point,Prec.W12);
        return ec_mulmuladd_W_inner(ecTemp, Prec, scalar_u, scalar_v, mm2, 4*computed_u + 2, 4*computed_v + 2);
    }
    if (quad_bit == 13) {
        let (ecTemp) = ec_add(quadruple_point,Prec.W13);
        return ec_mulmuladd_W_inner(ecTemp, Prec, scalar_u, scalar_v, mm2, 4*computed_u + 3, 4*computed_v + 2);
    }
    if (quad_bit == 14) {
        let (ecTemp) = ec_add(quadruple_point,Prec.W14);
        return ec_mulmuladd_W_inner(ecTemp, Prec, scalar_u, scalar_v, mm2, 4*computed_u + 2, 4*computed_v + 3);
    } 
    
    assert quad_bit = 15;
    let (ecTemp) = ec_add(quadruple_point,Prec.W15);
    return ec_mulmuladd_W_inner(ecTemp, Prec, scalar_u, scalar_v, mm2, 4*computed_u + 3 , 4*computed_v + 3);
}
