# SPECK

This repo contains the source code for the **SPECK (Signatures from Permutation Equivalence of Codes and Kernels)** signature scheme.

The repo is organized as follows:

- **[reference](reference/)** contains the source code for the reference implementation, compileable on multiple architectures.
- **[optimized](optimized/)** contains the source code for the optimized implementation, which leverages the **AVX2 instruction set**, available only on modern Intel CPUs, starting from the Haswell generation.
- **[scripts](scripts/)** contains utility files, in particular:
    - **[arrangements.sage](scripts/arrangements.sage)** is a collection of methods to count vectors, useful for the analysis of the attack complexity;
    - **[get_seedtree_vals.py](scripts/get_seedtree_vals.py)** is the file used to select parameters for the seedtree, took from the [CROSS repository](https://github.com/CROSS-signature/CROSS-implementation);
    - **[solver_evaluation.ipynb](scripts/solver_evaluation.ipynb)** is a jupyter notebook showing the theorical cost for the solver presented in the paper.

## Requirements

The following libraries/tools are needed:

- `cmake`
- `make`
- `gcc/clang`
- `openssl`
- `pkg-config`

Furthermore, as specified above, the optimized implementation runs only modern Intel CPUs, starting from the Haswell generation.

## Benchmarking

To benchmark SPECK the source code must first be compiled.

Compilation is performed as follows (for the optimized version just substitute `reference` with `optimized`):

```
cd reference 
mkdir build
cd build
cmake ..
make
```

To perform benchmarking just run the binary with the desired parameter set, e.g., for $n=252$, $t=133$:

```
./SPECK_benchmark_cat_252_133
```

The repository includes in the **[bench_suite](bench_suite/)** directory scripts for compiling and benchmarking LESS and PERK as well:

- To **compile** LESS, SPECK and PERK just run `./compile.sh`.
- To **perform benchmarks** run `python3 bench.py`.
- To **delete binaries** run `./clean.sh`.
