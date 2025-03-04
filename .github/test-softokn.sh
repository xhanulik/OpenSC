#!/bin/bash -e

function assert()
{
	if [[ $1 != 0 ]]; then
		echo "====> ERROR: $2"
		ERRORS=ERRORS + 1
	fi
}

echo "======================================================="
echo "Setup softtokn"
echo "======================================================="

# Setup paths
SOFTOKN_PWD="/usr/lib64/libsoftokn3.so"
TMPPDIR="$PWD/softokn"
TOKDIR="$TMPPDIR/tokens"

if [ -d "${TMPPDIR}" ]; then
    rm -fr "${TMPPDIR}"
fi
mkdir "${TMPPDIR}"
mkdir "${TOKDIR}"

if test -f "$SOFTOKN_PWD" ; then
	echo "Using softokn path $KRYOPTIC_PWD"
	P11LIB="$SOFTOKN_PWD"
else
	echo "softtokn not found"
	exit 0
fi

TOKENLABEL="NSS Certificate DB"
PINVALUE="12345678"
PINFILE="${TMPPDIR}/pinfile.txt"
echo ${PINVALUE} > "${PINFILE}"

echo 'Creating new NSS Database'
certutil -N -d $TOKDIR -f $PINFILE

# otherwise not working
export NSS_LIB_PARAMS=configDir=$TMPPDIR/tokens
PKCS11_TOOL="pkcs11-tool"
PUB_ARGS=("--module=${P11LIB}" "--token-label=${TOKENLABEL}")
PRIV_ARGS=("${PUB_ARGS[@]}" "--login" "--pin=${PINVALUE}")

echo "======================================================="
echo "Generate Keys"
echo "======================================================="

function generate_key() {
	TYPE="$1"
	ID="$2"
	LABEL="$3"

	echo "Generate $TYPE key (ID=$ID)"
	# Generate key pair
	$PKCS11_TOOL "${PRIV_ARGS[@]}" --keypairgen --key-type="$TYPE" --label="$LABEL" --id=$ID
	if [[ "$?" -ne "0" ]]; then
		echo "Couldn't generate $TYPE key pair"
		return 1
	fi

	# Extract public key from the card
	$PKCS11_TOOL "${PUB_ARGS[@]}" --read-object --id $ID --type pubkey --output-file ${TOKDIR}/$ID.der
	if [[ "$?" -ne "0" ]]; then
		echo "Couldn't read generated $TYPE public key"
		return 1
	fi

	# convert it to more digestible PEM format
	if [[ ${TYPE:0:3} == "RSA" ]]; then
		openssl rsa -inform DER -outform PEM -in ${TOKDIR}/$ID.der -pubin > ${TOKDIR}/$ID.pub
	elif [[ $TYPE == "EC:edwards25519" ]]; then
		openssl pkey -inform DER -outform PEM -in ${TOKDIR}/$ID.der -pubin > ${TOKDIR}/$ID.pub
	else
		openssl ec -inform DER -outform PEM -in ${TOKDIR}/$ID.der -pubin > ${TOKDIR}/$ID.pub
	fi
	rm ${TOKDIR}/$ID.der
}

generate_key "RSA:2048" "0001" "RSA2048" || return 1
generate_key "RSA:4096" "0002" "RSA4096" || return 1
generate_key "EC:secp256r1" "0003" "ECC_auth" || return 1
generate_key "EC:secp521r1" "0004" "ECC521" || return 1

echo "======================================================="
echo "Listing Objects"
echo "======================================================="
pkcs11-tool "${PUB_ARGS[@]}" -O
echo

echo "======================================================="
echo "Sign/Verify Test"
echo "======================================================="

# RSA tests
for HASH in "" "SHA224" "SHA256" "SHA384" "SHA512"; do
    RETOSSL="0"

    for SIGN_KEY in "0001" "0002"; do
        METHOD="RSA-PKCS"
        # RSA-PKCS works only on small data - generate small data:
        head -c 64 </dev/urandom > data # TODO change placing
        if [[ ! -z $HASH ]]; then
            METHOD="$HASH-$METHOD"
            # hash- methods should work on data > 512 bytes
            head -c 1024 </dev/urandom > data
        fi
        echo
        echo "-------------------------------------------------------"
        echo " ▸ $METHOD: Sign & Verify (KEY $SIGN_KEY)"
        echo "-------------------------------------------------------"
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --id $SIGN_KEY -s -m $METHOD --input-file data --output-file data.sig
        assert $? "Failed to Sign data"

        # OpenSSL verification
        echo -n "Verification by OpenSSL: "
        if [[ -z $HASH ]]; then
            openssl pkeyutl -verify -inkey ${TOKDIR}/$SIGN_KEY.pub -in data -sigfile data.sig -pubin
        else
            openssl dgst -keyform PEM -verify ${TOKDIR}/$SIGN_KEY.pub -${HASH,,*} \
                   -signature data.sig data
        fi
        if [[ "$RETOSSL" == "0" ]]; then
            assert $? "Failed to Verify signature using OpenSSL"
        elif [[ "$?" == "0" ]]; then
            assert 1 "Unexpectedly Verified signature using OpenSSL"
        fi

        # pkcs11-tool verification
        echo "Verification by pkcs11-tool:"
        $PKCS11_TOOL "${PUB_ARGS[@]}" --id $SIGN_KEY --verify -m $METHOD \
               --input-file data --signature-file data.sig
        assert $? "Failed to Verify signature using pkcs11-tool"
        rm data.sig

        # -PSS methods fail since softokn has MODULUS_BITS attribute invalid
    done
done

# ECDSA tests
head -c 1024 </dev/urandom > data
for SIGN_KEY in "0003" "0004"; do
    METHOD="ECDSA"

    echo
    echo "-------------------------------------------------------"
    echo " ▸ $METHOD: Sign & Verify (KEY $SIGN_KEY)"
    echo "-------------------------------------------------------"
    openssl dgst -binary -sha256 data > data.hash
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --id $SIGN_KEY -s -m $METHOD \
        --input-file data.hash --output-file data.sig
    assert $? "Failed to Sign data"
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --id $SIGN_KEY -s -m $METHOD \
        --input-file data.hash --output-file data.sig.openssl \
        --signature-format openssl
    assert $? "Failed to Sign data into OpenSSL format"

    # OpenSSL verification
    echo -n "Verification by OpenSSL: "
    openssl dgst -keyform PEM -verify ${TOKDIR}/$SIGN_KEY.pub -sha256 \
               -signature data.sig.openssl data
    assert $? "Failed to Verify signature using OpenSSL"

    # pkcs11-tool verification
    echo "Verification by pkcs11-tool:"
    $PKCS11_TOOL "${PUB_ARGS[@]}" --id $SIGN_KEY --verify -m $METHOD \
           --input-file data.hash --signature-file data.sig
    assert $? "Failed to Verify signature using pkcs11-tool"
    rm data.sig{,.openssl} data.hash
done
echo

echo "======================================================="
echo "Encrypt/Decrypt Test"
echo "======================================================="

METHOD="RSA-PKCS"
head -c 64 </dev/urandom > data
for ENC_KEY in "0001" "0002"; do
    echo
    echo "-------------------------------------------------------"
    echo " ▸ $METHOD: Decrypt (KEY $ENC_KEY)"
    echo "-------------------------------------------------------"
    # OpenSSL Encryption
    openssl pkeyutl -encrypt -inkey ${TOKDIR}/$ENC_KEY.pub -in data -pubin -out data.crypt
    assert $? "Failed to encrypt data using OpenSSL"
    # pkcs11-tool Decryption
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --id $ENC_KEY --decrypt -m $METHOD \
            --input-file data.crypt > data.decrypted
    assert $? "Failed to Decrypt data"
    diff data{,.decrypted}
    assert $? "The decrypted data do not match the original"
    rm data.{crypt,decrypted}
    echo "Decryption is valid"
done
rm data
echo

echo "======================================================="
echo "Test import of keys"
echo "======================================================="

for KEYTYPE in "RSA" "EC" ; do
    echo "-------------------------------------------------------"
    echo " ▸ Generate and import $KEYTYPE keys"
    echo "-------------------------------------------------------"
    ID="0100"
    OPTS="-pkeyopt rsa_keygen_bits:2048"
    if [ "$KEYTYPE" == "EC" ]; then
        ID="0200"
        OPTS="-pkeyopt ec_paramgen_curve:P-256" 
    fi
    openssl genpkey -out "${KEYTYPE}_private.der" -outform DER -algorithm $KEYTYPE $OPTS

    assert $? "Failed to generate private $KEYTYPE key"
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --write-object "${KEYTYPE}_private.der" --id "$ID" \
        --type privkey --label "$KEYTYPE"
    assert $? "Failed to write private $KEYTYPE key"
    echo "Private key written"

    openssl pkey -in "${KEYTYPE}_private.der" -out "${KEYTYPE}_public.der" -pubout -inform DER -outform DER
    assert $? "Failed to convert private $KEYTYPE key to public"
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --write-object "${KEYTYPE}_public.der" --id "$ID" --type pubkey --label "$KEYTYPE"
    assert $? "Failed to write public $KEYTYPE key"
    echo "Public key written"

    rm "${KEYTYPE}_private.der" "${KEYTYPE}_public.der"
done
