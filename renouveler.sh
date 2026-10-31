#!/usr/bin/env bash
# Renouvelle le certificat de www.tp.local s'il expire dans moins de SEUIL jours.
# A lancer depuis le dossier de l'IGC (celui qui contient inter.cnf).
set -euo pipefail
umask 077

IGC="${IGC:-$(cd "$(dirname "$0")" && pwd)}"
TLS=/etc/nginx/tls
SEUIL_JOURS="${SEUIL_JOURS:-30}"
FORCER="${1:-}"
cd "$IGC"

# 0. Faut-il renouveler ?  (-checkend : code 0 si encore valide dans N secondes)
if [[ "$FORCER" != "--force" ]] && \
   openssl x509 -checkend $((SEUIL_JOURS * 86400)) -noout -in "$TLS/serveur_chaine.crt" >/dev/null; then
  echo "Certificat valable plus de $SEUIL_JOURS jours : rien a faire."
  exit 0
fi

TRAVAIL=$(mktemp -d)
trap 'rm -rf "$TRAVAIL"' EXIT
DATE=$(date +%Y%m%d-%H%M%S)

# 1. Nouvelle cle et nouvelle demande
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TRAVAIL/serveur.key"
openssl req -new -key "$TRAVAIL/serveur.key" -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out "$TRAVAIL/serveur.csr"

# 2. Signature par l'intermediaire
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
  -in "$TRAVAIL/serveur.csr" -out "$TRAVAIL/serveur.crt"

# 3. Verifications AVANT tout deploiement
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local "$TRAVAIL/serveur.crt"
# la cle correspond-elle au certificat ?
[[ "$(openssl pkey -in "$TRAVAIL/serveur.key" -pubout)" == \
   "$(openssl x509 -in "$TRAVAIL/serveur.crt" -noout -pubkey)" ]] \
  || { echo "Cle et certificat ne correspondent pas" >&2; exit 1; }
cat "$TRAVAIL/serveur.crt" inter/inter.crt > "$TRAVAIL/serveur_chaine.crt"

# 4. Sauvegarde de l'ancien couple (retour arriere possible)
mkdir -p "$TLS/archive"
cp -p "$TLS/serveur.key"          "$TLS/archive/serveur.key.$DATE"
cp -p "$TLS/serveur_chaine.crt"   "$TLS/archive/serveur_chaine.crt.$DATE"

# 5. Installation, test de configuration, rechargement sans coupure
install -m 600 "$TRAVAIL/serveur.key"         "$TLS/serveur.key"
install -m 644 "$TRAVAIL/serveur_chaine.crt"  "$TLS/serveur_chaine.crt"
if nginx -t; then
  nginx -s reload            # ou : systemctl reload nginx
  echo "Certificat renouvele (ancien conserve sous $TLS/archive/*.$DATE)."
else
  echo "Configuration invalide : retour arriere." >&2
  cp -p "$TLS/archive/serveur.key.$DATE"        "$TLS/serveur.key"
  cp -p "$TLS/archive/serveur_chaine.crt.$DATE" "$TLS/serveur_chaine.crt"
  exit 1
fi
