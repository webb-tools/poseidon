// @ts-check
import("../pkg/index.js")
  .then(pkg => {
    console.time('Creating PoseidonHasher without cached gens');
    const opts1 = new pkg.PoseidonHasherOptions();
    new pkg.PoseidonHasher(opts1);
    console.timeEnd('Creating PoseidonHasher without cached gens');

    const opts2 = new pkg.PoseidonHasherOptions();
    // we pay the time for ser/de the values tho!
    const gens = opts2.bp_gens; // regenerate the gens (if not already there).
    opts2.bp_gens = gens;
    console.time('Creating PoseidonHasher with cached gens');
    new pkg.PoseidonHasher(opts2);
    console.timeEnd('Creating PoseidonHasher with cached gens');
  })
  .catch(console.error);
