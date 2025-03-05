#!/bin/bash -e

source "./pkcs11-common.sh"

heading "Setup Kryoptic"

# build kryoptic
if [ ! -d "kryoptic" ]; then
	git clone https://github.com/latchset/kryoptic.git
fi
pushd kryoptic
git submodule init
git submodule update
cargo build --features dynamic,standard,nssdb
popd

# set paths
KRYOPTIC_PWD="$PWD/kryoptic/target/debug/libkryoptic_pkcs11.so"
if test -f "$KRYOPTIC_PWD" ; then
	echo "Using kryoptic path $KRYOPTIC_PWD"
	P11LIB="$KRYOPTIC_PWD"
else
	echo "Kryoptic not found"
	exit 0
fi

TMPPDIR="$PWD/kryoptic/tmp"
export TOKDIR="$TMPPDIR/tokens"
if [ -d "${TMPPDIR}" ]; then
    rm -fr "${TMPPDIR}"
fi
mkdir -p "${TMPPDIR}"
mkdir "${TOKDIR}"


heading "Initialize Kryoptic Token"
export KRYOPTIC_CONF="${KRYOPTIC_CONF:-$TOKDIR/kryoptic.sql}"
export TOKENCONFIGVARS="export KRYOPTIC_CONF=$TOKDIR/kryoptic.sql"
export TOKENLABEL="Kryoptic Token"
export PKCS11_TOOL="pkcs11-tool"
export PINVALUE="123456"

# init token
$PKCS11_TOOL --module "${P11LIB}" --init-token \
    --label "${TOKENLABEL}" --so-pin "${PINVALUE}"
# set pin
$PKCS11_TOOL --module "${P11LIB}" --so-pin "${PINVALUE}" \
    --login --login-type so --init-pin --pin "${PINVALUE}"

# setup file with auxiliary functions
export PUB_ARGS=("--module=${P11LIB}" "--token-label=${TOKENLABEL}")
export PRIV_ARGS=("${PUB_ARGS[@]}" "--login" "--pin=${PINVALUE}")
source "./pkcs11-common.sh"
echo


heading "Generate Keys"
generate_key "RSA:2048" "0001" "RSA2048" || return 1
generate_key "RSA:4096" "0002" "RSA4096" || return 1
generate_key "EC:secp256r1" "0003" "ECC_auth" || return 1
generate_key "EC:secp521r1" "0004" "ECC521" || return 1


echo "Listing Objects"
pkcs11-tool "${PUB_ARGS[@]}" -O
echo


heading "The pkcs11-tool Test"
$PKCS11_TOOL "${PRIV_ARGS[@]}" --test | grep " errors"
assert $? "Failed running tests"

echo "Sign/Verify Test"

# RSA tests
for HASH in "" "SHA224" "SHA256" "SHA384" "SHA512"; do
    for SIGN_KEY in "0001" "0002"; do
        test_rsa_pkcs_sign_verify "$HASH" "$SIGN_KEY"
        test_rsa_pkcs_pss_sign_verify "$HASH" "$SIGN_KEY"
    done
done

# ECDSA tests
for SIGN_KEY in "0003" "0004"; do
    test_ecdsa_sign_verify "$SIGN_KEY"
done
echo

heading "Encrypt/Decrypt Test"
for ENC_KEY in "0001" "0002"; do
    test_rsa_pkcs_decrypt "$ENC_KEY"
done
# RSA-PKCS-OAEP decryption by pkcs11-tool returns
# error: PKCS11 function C_DecryptUpdate failed: rv = CKR_OPERATION_NOT_INITIALIZED (0x91)


heading "Test key-pair with CKA_ALLOWED_MECHANISMS"
ID="0006"
MECHANISMS="RSA-PKCS,SHA1-RSA-PKCS,RSA-PKCS-PSS"
# Generate key pair
$PKCS11_TOOL "${PRIV_ARGS[@]}" --keypairgen --key-type="RSA:2048" --label="test" --id="$ID" \
	--allowed-mechanisms="$MECHANISMS,SHA384-RSA-PKCS"
assert $? "Failed to Generate RSA key pair"

# Check the attributes are visible
$PKCS11_TOOL "${PRIV_ARGS[@]}" --list-objects --id=$ID &> objects.list
assert $? "Failed to list objects"
grep -q "Allowed mechanisms" objects.list
assert $? "Allowed mechanisms not in the object list"
grep -q "$MECHANISMS" objects.list
assert $? "The $MECHANISMS is not in the list"
rm -f objects.list

# Make sure we are not allowed to use forbidden mechanism
echo "data to sign (max 100 bytes)" > data
$PKCS11_TOOL "${PRIV_ARGS[@]}" --id $ID -s -m SHA256-RSA-PKCS \
       --input-file data --output-file data.sig &> sign.log || grep -q CKR_MECHANISM_INVALID sign.log
assert $? "It was possible to sign using non-allowed mechanism"
rm -f data{,.sig}
echo
echo "CKA_ALLOWED_MECHANISMS working correctly"
echo


heading "Test import of keys"
for KEYTYPE in "RSA" "EC" ; do
    test_import_key "$KEYTYPE"
done

clean
exit $ERRORS
