#!/bin/bash
set -e

REPORT_FILE="../docs/SECURITY.md"
TARGETS=$(ls fuzz_targets/*.rs | xargs -n 1 basename | sed 's/\.rs//')

for target in $TARGETS; do
    stats=$(cargo +nightly fuzz run "$target" -- -runs=0 2>&1 | grep "DONE" | tail -n 1) || true
    
    if [ -n "$stats" ]; then
        cov=$(echo "$stats" | grep -oP 'cov: \K[0-9]+' || echo "0")
        ft=$(echo "$stats" | grep -oP 'ft: \K[0-9]+' || echo "0")
        corp=$(echo "$stats" | grep -oP 'corp: \K[0-9]+/[0-9]+[a-zA-Z]+' || echo "0")
        
        sed -i "s#| \`$target\` |.*#| \`$target\` | $cov | $ft | $corp |#" "$REPORT_FILE"
    fi
done

total_seeds=$(find corpus -type f | wc -l)
total_size=$(du -sh corpus | cut -f1)
last_update=$(date +%Y-%m-%d)
total_crashes=$(find artifacts -name "crash-*" -type f 2>/dev/null | wc -l || echo "0")

sed -i "s/- \*\*Corpus\*\*: .*/- \*\*Corpus\*\*: $total_seeds seeds ($total_size, minimized)/" "$REPORT_FILE"
sed -i "s/- \*\*Last Updated\*\*: .*/- \*\*Last Updated\*\*: $last_update/" "$REPORT_FILE"
sed -i "s/- \*\*Crashes Found\*\*: .*/- \*\*Crashes Found\*\*: $total_crashes/" "$REPORT_FILE"
