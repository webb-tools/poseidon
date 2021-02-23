import("../pkg/index.js")
  .then(pkg => {
    console.time('Creating PoseidonHasher');
    pkg.PoseidonHasher.new();
    console.timeEnd('Creating PoseidonHasher');
  })
  .catch(console.error);
