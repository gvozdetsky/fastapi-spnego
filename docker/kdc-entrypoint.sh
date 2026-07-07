#!/usr/bin/env bash
# Bring up a throwaway MIT Kerberos KDC for the dev/test environment.
#
# Creates the realm database, a service principal for the app, and a user
# principal for the test client, then exports the service keytab to the shared
# volume and runs the KDC in the foreground.
set -euo pipefail

REALM="EXAMPLE.COM"
MASTER_PW="masterpassword"
# Use an FQDN: MIT krb5 appends a trailing dot to single-label hostnames when
# forming a principal, which would break the SPN match. app.example.com does not.
SERVICE_PRINC="HTTP/app.example.com@${REALM}"
USER_PRINC="alice@${REALM}"
USER_PW="alicepassword"
KEYTAB="/keytab/app.keytab"

# Fresh database on every start (the container is ephemeral).
kdb5_util create -s -r "$REALM" -P "$MASTER_PW"

# Service principal the app authenticates as. +ok_as_delegate lets clients that
# opt in forward (delegate) their TGT so we can exercise the delegation path.
kadmin.local -q "addprinc -randkey ${SERVICE_PRINC}"
kadmin.local -q "modprinc +ok_as_delegate ${SERVICE_PRINC}"

# Test user. Forwardable so `kinit -f` can delegate to the service.
kadmin.local -q "addprinc -pw ${USER_PW} +requires_preauth ${USER_PRINC}"

# Export the service keytab to the volume the app mounts read-only.
rm -f "$KEYTAB"
kadmin.local -q "ktadd -k ${KEYTAB} ${SERVICE_PRINC}"
chmod 644 "$KEYTAB"

echo "KDC ready: realm=${REALM} service=${SERVICE_PRINC} user=${USER_PRINC}"

# Run in the foreground so the container stays alive.
exec krb5kdc -n
