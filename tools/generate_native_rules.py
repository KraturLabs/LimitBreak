"""Generate C++ rule strings from the same source used by Python discovery."""
import argparse
from pathlib import Path
import discovery_rules

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('output', type=Path)
args = parser.parse_args()
lines = ['// Generated from tools/discovery_rules.py; do not edit.', '#pragma once',
         'namespace limitbreak::discovery::rules {']
for name, value in vars(discovery_rules).items():
    if name.isupper() and isinstance(value, str):
        assert ')LB_RULE"' not in value
        lines.append(f'inline constexpr char {name}[] = R"LB_RULE({value})LB_RULE";')
lines.append('}')
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text('\n'.join(lines)+'\n', encoding='utf-8')
