use bulletproofs::BulletproofGens;
use curve25519_gadgets::poseidon::{
    builder::{Poseidon, PoseidonBuilder},
    gen_mds_matrix, gen_round_keys, PoseidonSbox,
};
use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, this uses `wee_alloc` as the global
// allocator.
//
// If you don't want to use `wee_alloc`, you can safely delete this.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen(start)]
pub fn set_panic_hook() {
    // `set_panic_hook`is called once during initialization
    // we are printing useful errors when out code panics
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub struct PoseidonHasher {
    inner: Poseidon,
}

impl Default for PoseidonHasher {
    fn default() -> Self { Self::new() }
}

#[wasm_bindgen]
impl PoseidonHasher {
    pub fn new() -> Self {
        let width = 6;
        let (full_b, full_e) = (4, 4);
        let partial_rounds = 57;
        let inner = PoseidonBuilder::new(width)
            .num_rounds(full_b, full_e, partial_rounds)
            .round_keys(gen_round_keys(width, full_b + full_e + partial_rounds))
            .mds_matrix(gen_mds_matrix(width))
            .sbox(PoseidonSbox::Inverse)
            .bulletproof_gens(BulletproofGens::new(4096, 1))
            .build();
        Self { inner }
    }
}
