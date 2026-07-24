#!/bin/bash
# Summarize run_bench.sh logs: pair algo compute_median apply_median size verified
cd "${BENCH_DIR:-.}/results" || exit 1
printf "%-16s %-15s %10s %10s %12s %s\n" PAIR ALGO COMPUTE APPLY SIZE VERIFIED
for log in *.log; do
    name=${log%.log}; pair=$name; algo=hdiff
    compute=$(grep -oP 'compute time \K[0-9.]+(?=ms)' "$log" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
    compute_s=$(grep -oP 'compute time \K[0-9.]+(?=s$)' "$log" | grep -v m | sort -n | awk '{a[NR]=$1} END{if (NR>0) print a[int((NR+1)/2)]*1000}')
    [[ -z "$compute" && -n "$compute_s" ]] && compute=$compute_s
    apply=$(grep -oP 'apply time \K[0-9.]+(?=ms)' "$log" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
    apply_s=$(grep -oP 'apply time \K[0-9.]+(?=s$)' "$log" | grep -v m | sort -n | awk '{a[NR]=$1} END{if (NR>0) print a[int((NR+1)/2)]*1000}')
    [[ -z "$apply" && -n "$apply_s" ]] && apply=$apply_s
    size=$(grep -oP 'Diff size: \K[0-9]+' "$log")
    verified=$(grep -q "Verification OK" "$log" && echo OK || echo FAIL)
    printf "%-16s %-15s %8sms %8sms %12s %s\n" "$pair" "$algo" "$compute" "$apply" "$size" "$verified"
done
