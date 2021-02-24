use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_gadgets::poseidon::{
    builder::{Poseidon, PoseidonBuilder},
    gen_mds_matrix, gen_round_keys, PoseidonSbox,
};
use js_sys::Uint8Array;
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
pub struct PoseidonHasherOptions {
    /// The size of the permutation, in field elements.
    width: usize,
    /// Number of full SBox rounds in beginning
    pub full_rounds_beginning: Option<usize>,
    /// Number of full SBox rounds in end
    pub full_rounds_end: Option<usize>,
    /// Number of partial rounds
    pub partial_rounds: Option<usize>,
    /// The desired (classical) security level, in bits.
    pub security_bits: Option<usize>,
    /// Bulletproof generators for proving/verifying (serialized)
    #[wasm_bindgen(skip)]
    pub bp_gens: Option<BulletproofGens>,
}

impl Default for PoseidonHasherOptions {
    fn default() -> Self {
        Self {
            width: 6,
            full_rounds_beginning: None,
            full_rounds_end: None,
            partial_rounds: None,
            security_bits: None,
            bp_gens: None,
        }
    }
}

#[wasm_bindgen]
impl PoseidonHasherOptions {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self { Self::default() }

    #[wasm_bindgen(setter)]
    pub fn set_bp_gens(&mut self, value: Uint8Array) {
        let bp_gens: BulletproofGens = bincode::deserialize(&value.to_vec())
            .unwrap_or_else(|_| BulletproofGens::new(4096, 1));
        self.bp_gens = Some(bp_gens);
    }

    #[wasm_bindgen(getter)]
    pub fn bp_gens(&self) -> Uint8Array {
        let val = self
            .bp_gens
            .clone()
            .unwrap_or_else(|| BulletproofGens::new(4096, 1));
        let serialized =
            bincode::serialize(&val).unwrap_or_else(|_| Vec::new());
        Uint8Array::from(serialized.as_slice())
    }
}

#[wasm_bindgen]
pub struct PoseidonHasher {
    inner: Poseidon,
}

#[wasm_bindgen]
impl PoseidonHasher {
    pub fn default() -> Self { Self::with_options(Default::default()) }

    #[wasm_bindgen(constructor)]
    pub fn with_options(opts: PoseidonHasherOptions) -> Self {
        let full_rounds_beginning = opts.full_rounds_beginning.unwrap_or(3);
        let full_rounds_end = opts.full_rounds_end.unwrap_or(3);
        let partial_rounds = opts.partial_rounds.unwrap_or(57);

        // default pedersen genrators
        let pc_gens = PedersenGens::default();
        let bp_gens = opts
            .bp_gens
            .clone()
            .unwrap_or_else(|| BulletproofGens::new(4096, 1));

        let total_rounds =
            full_rounds_beginning + full_rounds_end + partial_rounds;
        let inner = PoseidonBuilder::new(opts.width)
            .num_rounds(full_rounds_beginning, full_rounds_end, partial_rounds)
            .round_keys(gen_round_keys(opts.width, total_rounds))
            .mds_matrix(gen_mds_matrix(opts.width))
            .sbox(PoseidonSbox::Inverse)
            .bulletproof_gens(bp_gens)
            .pedersen_gens(pc_gens)
            .build();
        Self { inner }
    }
}
