#!/bin/bash -e

source "./pkcs11-common.sh"

heading "Setup softtokn"

# find softokn PKCS#11 module path
softokn_paths=(
    "/usr/lib64/libsoftokn3.so" # Fedora
    "/usr/lib/x86_64-linux-gnu/libsoftokn3.so" # Ubuntu
)
P11LIB=""
for lib in "${softokn_paths[@]}"; do
    if [ -f "$lib" ]; then
        echo "Using softokn path $lib"
        P11LIB="$lib"
        break
    fi
done
if [ -z "$P11LIB" ]; then
    echo "Unable to find softokn PKCS#11 library"
    exit 1
fi

TMPPDIR="$PWD/softokn"
export TOKDIR="$TMPPDIR/tokens"
if [ -d "${TMPPDIR}" ]; then
    rm -fr "${TMPPDIR}"
fi
mkdir "${TMPPDIR}"
mkdir "${TOKDIR}"


heading "Initialize softokn"
TOKENLABEL="NSS Certificate DB"
PINVALUE="12345678"
PINFILE="${TMPPDIR}/pinfile.txt"
echo ${PINVALUE} > "${PINFILE}"

certutil -N -d $TOKDIR -f $PINFILE

# otherwise not working
export NSS_LIB_PARAMS=configDir=$TMPPDIR/tokens
export PKCS11_TOOL="pkcs11-tool"
export PUB_ARGS=("--module=${P11LIB}" "--token-label=${TOKENLABEL}")
export PRIV_ARGS=("${PUB_ARGS[@]}" "--login" "--pin=${PINVALUE}")
source "./pkcs11-common.sh"


heading "Generate Keys"
generate_key "RSA:2048" "0001" "RSA2048" || return 1
generate_key "RSA:4096" "0002" "RSA4096" || return 1
generate_key "EC:secp256r1" "0003" "ECC_auth" || return 1
generate_key "EC:secp521r1" "0004" "ECC521" || return 1


heading "Listing Objects"
pkcs11-tool "${PUB_ARGS[@]}" -O
echo


heading "Sign/Verify Test"
# RSA tests
for HASH in "" "SHA224" "SHA256" "SHA384" "SHA512"; do
    for SIGN_KEY in "0001" "0002"; do
        test_rsa_pkcs_sign_verify "$HASH" "$SIGN_KEY"

        # -PSS methods fail since softokn has MODULUS_BITS attribute invalid
    done
done

# ECDSA tests
for SIGN_KEY in "0003" "0004"; do
     test_ecdsa_sign_verify "$SIGN_KEY"
done


heading "Encrypt/Decrypt Test"
for ENC_KEY in "0001" "0002"; do
    test_rsa_pkcs_decrypt "$ENC_KEY"
done
# RSA-PKCS-OAEP decryption by pkcs11-tool returns
# error: PKCS11 function C_DecryptUpdate failed: rv = CKR_OPERATION_NOT_INITIALIZED (0x91)


heading "Test import of keys"
for KEYTYPE in "RSA" "EC" ; do
    test_import_key "$KEYTYPE"
done


clean
exit $ERRORS
