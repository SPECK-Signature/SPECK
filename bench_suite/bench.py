import subprocess
import time
import argparse
import os
import sys

import matplotlib.pyplot as plt

import itertools

def get_script_path():
    return os.path.dirname(os.path.realpath(sys.argv[0]))

# Check turboboost disabled

def check_turbo_boost():
    check_cmd = "cat $(find /sys/devices/system/cpu/ -iname '*no_turbo' | head -n 1)"
    turbo_boost_disabled = subprocess.run(check_cmd, shell=True, capture_output=True).stdout.decode()
    if turbo_boost_disabled == '0\n':
        print("Turbo boost is not disabled! This will affect benchmarking results.")
        file_cmd = "find /sys/devices/system/cpu/ -iname '*no_turbo' | head -n 1"
        turbo_boost_file = subprocess.run(file_cmd, shell=True, capture_output=True).stdout.decode()
        disable_tb_cmd = f"echo 1 | sudo tee {turbo_boost_file}"
        print(f"To disable it run {disable_tb_cmd}")
        time.sleep(0.5)

def check_scaling_governor():
    check_cmd = "cat $(find /sys/devices/system/cpu -iname '*scaling_governor') | grep powersave | wc -l"
    powersave_cpus = int(subprocess.run(check_cmd, shell=True, capture_output=True).stdout.decode())
    if powersave_cpus > 0:
        print("CPU is set to powersave mode! This will affected benchmarking results.")
        print("Set it to performance mode using a system utility, e.g. `sudo cpupower frequency-set -g performance`")
        time.sleep(0.5)

benchmarks = {}
# benchmark['<scheme-name>'] = [kg-cycles,kg-time,sign-cycles,sign-times,ver-cycles,ver-times,sign-size]


def run_benchs(name,pairs):
    print(f"=========================={name.upper()}==========================")
    print("")
    script_dir = get_script_path()
    bench_struct = []
    for pair in pairs:
        if not os.path.exists(pair[1]):
            print(f"Binary not found, have you compiled {pair[0].split('_')[0].upper()}? Run compile.sh")
            break
        cmd = f"{script_dir+pair[1][1:]} 2>/dev/null | grep -oP '[0-9]*\\.?[0-9]*'"
        result = subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
        values = [float(val) for val in result.split() if val]
        # values = [KCycles AVG, KCycles STDDEV, milliseconds AVG]
        print(f"-------------------{pair[0]}-------------------")
        print(f"KEYGEN: {values[0]:>10.2f} KCycles {values[2]:>10.2f} ms")
        print(f"SIGN:   {values[3]:>10.2f} KCycles {values[5]:>10.2f} ms")
        print(f"VERIFY: {values[7]:>10.2f} KCycles {values[9]:>10.2f} ms")
        print(f"SIZE:   {values[6]:>20} Bytes ")
        #benchmarks[pair[0]] = [values[0],values[2], values[3], values[5], values[7], values[9], values[6]]
        bench_struct.append([pair[0],[values[0],values[2], values[3], values[5], values[7], values[9], values[6]]])
        time.sleep(0.01)
        print("")
    benchmarks[name] = bench_struct
    print("")

speck_pairs = [
    ['speck_252_133', './../optimized/build/SPECK_benchmark_cat_252_133'],
    ['speck_252_256', './../optimized/build/SPECK_benchmark_cat_252_256'],
    ['speck_252_512', './../optimized/build/SPECK_benchmark_cat_252_512'],
    ['speck_252_768', './../optimized/build/SPECK_benchmark_cat_252_768'],
    ['speck_252_4096', './../optimized/build/SPECK_benchmark_cat_252_4096']
]

perk_pairs = [
    ['perk-1-fast-aes_aes','./perk/perk-1-fast-aes_aes/build/bin/bench'],
    ['perk-1-short-aes_aes','./perk/perk-1-short-aes_aes/build/bin/bench'],
    ['perk-1-fast-aes_keccak','./perk/perk-1-fast-aes_keccak/build/bin/bench'],
    ['perk-1-short-aes_keccak','./perk/perk-1-short-aes_keccak/build/bin/bench'],
    ['perk-1-fast-keccak_keccak','./perk/perk-1-fast-keccak_keccak/build/bin/bench'],
    ['perk-1-short-keccak_keccak','./perk/perk-1-fast-keccak_keccak/build/bin/bench'],
]

less_pairs = [
    ['less_252_45','./less/Optimized_Implementation/avx2/build/LESS_benchmark_cat_252_45'],
    ['less_252_68','./less/Optimized_Implementation/avx2/build/LESS_benchmark_cat_252_68'],
    ['less_252_192','./less/Optimized_Implementation/avx2/build/LESS_benchmark_cat_252_192']
]

if __name__ == "__main__":
    print(f"Benchmarking Times (average of 128 runs)")
    check_turbo_boost()
    check_scaling_governor()
    run_benchs('less',less_pairs)
    run_benchs('perk',perk_pairs)
    run_benchs('speck',speck_pairs)
