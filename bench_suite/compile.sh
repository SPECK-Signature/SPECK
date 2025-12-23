#!/bin/bash
set -e # Exit if something goes wrong
bench_dir=$(dirname $(realpath $0))

while true; do
    read -p "Do you wish to recompile all schemes? " yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer y/n.";;
    esac
done

echo "Starting compilation of all schemes!"

# LESS

echo "Starting LESS compilation"

cd $bench_dir/less/Optimized_Implementation/avx2
rm -rf build
mkdir build
cd build
cmake ..
make -j8
cd $bench_dir

echo "LESS compiled successfully"

# PERK

echo "Starting PERK compilation"

for target in perk-1-fast-aes_aes perk-1-short-aes_aes perk-1-fast-aes_keccak perk-1-short-aes_keccak perk-1-fast-keccak_keccak perk-1-short-keccak_keccak; do
    (cd "$bench_dir/perk/$target" && make -j8)
done
cd $bench_dir

echo "PERK compiled successfully"

echo "ALL SCHEMES COMPILED SUCCESFULLY!"

# SPECK

echo "Starting SPECK compilation"

cd $bench_dir/../optimized
rm -rf build
mkdir build
cd build
cmake ..
make -j8
cd $bench_dir

echo "SPECK compiled successfully"
