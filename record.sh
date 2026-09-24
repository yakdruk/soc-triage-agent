#!/bin/zsh
# Records the README GIF. Run with your key exported:
#   export GOOGLE_API_KEY=...
#   ./record.sh
set -e
cd "$(dirname "$0")"

: "${GOOGLE_API_KEY:?export GOOGLE_API_KEY first (aistudio.google.com/apikey)}"
export GOOGLE_GENAI_USE_VERTEXAI=FALSE
export MODEL="${MODEL:-gemini-3.1-flash-lite}"
PY=~/.venv/bin/python

cat > /tmp/_soc_take.sh <<'INNER'
cd ~/dev/soc-triage-agent
PY=~/.venv/bin/python
printf '$ python3 demo.py 2\n'; sleep 1
$PY demo.py 2
printf '\n$ python3 demo.py 4\n'; sleep 1
$PY demo.py 4
sleep 3
INNER
chmod +x /tmp/_soc_take.sh

rm -f demo.cast demo.gif
asciinema rec demo.cast --cols 112 --rows 34 --overwrite -c "zsh /tmp/_soc_take.sh"
agg --font-size 16 --theme asciinema --speed 1.4 --idle-time-limit 2 demo.cast demo.gif
rm -f demo.cast /tmp/_soc_take.sh
ls -lh demo.gif
