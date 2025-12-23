#!/bin/bash
set -e # Exit if something goes wrong
bench_dir=$(dirname $(realpath $0))

while true; do
    read -p "Do you wish to clean all binaries? " yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer y/n.";;
    esac
done

echo "Starting binaries removal!"

# LESS

echo "Cleaning LESS"

cd $bench_dir/less/Optimized_Implementation/avx2
rm -rf build
cd $bench_dir

echo "LESS binaries removed successfully"

# SPECK

echo "Cleaning SPECK"

cd $bench_dir/../optimized
rm -rf build
cd $bench_dir

echo "SPECK binaries removed successfully"

# PERK

echo "Cleaning PERK"

for target in perk-1-fast-aes_aes perk-1-short-aes_aes perk-1-fast-aes_keccak perk-1-short-aes_keccak perk-1-fast-keccak_keccak perk-1-short-keccak_keccak; do
    (cd $bench_dir/perk/$target && make clean)
done
cd $bench_dir

echo "PERK binaries removed successfully"

echo "ALL BINARIES REMOVED SUCCESFULLY!"
