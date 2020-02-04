#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

"$DIR/switch_power.py" off
sleep $1
"$DIR/switch_power.py" on