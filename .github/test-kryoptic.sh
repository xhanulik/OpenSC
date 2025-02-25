#!/bin/bash -e

echo running test
exit

PKCS11_TOOL="/home/vhanulik/devel/OpenSC/src/tools/.libs/pkcs11-tool" # TODO: adjust for BUILD_PATH

ERRORS=0
function assert()
{
    echo "Error value: $1"
	if [[ $1 != 0 ]]; then
		echo "====> ERROR: $2"
		ERRORS=ERRORS + 1
	fi
}

echo "======================================================="
echo "Setup Kryoptic"
echo "======================================================="

# search for kryoptic
KRYOPTIC_PWD="/home/vhanulik/devel/kryoptic/target/debug/libkryoptic_pkcs11.so"
TMPPDIR="/home/vhanulik/devel/OpenSC/tmp/kryoptic"
TOKDIR="$TMPPDIR/tokens"


# remove the possibly existing directories
if [ -d "${TMPPDIR}" ]; then
    rm -fr "${TMPPDIR}"
fi
mkdir -p "${TMPPDIR}"
mkdir "${TOKDIR}"

if test -f "$KRYOPTIC_PWD" ; then
	echo "Using kryoptic path $KRYOPTIC_PWD"
	P11LIB="$KRYOPTIC_PWD"
else
	echo "Kryoptic not found"
	exit 0
fi
echo

# create database for kryoptic
export KRYOPTIC_CONF="${KRYOPTIC_CONF:-$TOKDIR/kryoptic.sql}"
export TOKENLABEL="Kryoptic Token"
export TOKENLABELURI="Kryoptic%20Token"
PINVALUE="123456"
PINFILE="${TMPPDIR}/pinfile.txt"
echo ${PINVALUE} > "${PINFILE}"
PKCS11_DEBUG_FILE="${TMPPDIR}/pkcs11-test.log"

echo "======================================================="
echo "Initialize Kryoptic Token"
echo "======================================================="

# init token
pkcs11-tool --module "${P11LIB}" --init-token \
    --label "${TOKENLABEL}" --so-pin "${PINVALUE}"
# set pin
pkcs11-tool --module "${P11LIB}" --so-pin "${PINVALUE}" \
    --login --login-type so --init-pin --pin "${PINVALUE}"

export TOKENCONFIGVARS="export KRYOPTIC_CONF=$TOKDIR/kryoptic.sql"
export PKCS11_PROVIDER_MODULE=$P11LIB
PUB_ARGS=("--module=${P11LIB}" "--token-label=${TOKENLABEL}")
PRIV_ARGS=("${PUB_ARGS[@]}" "--login" "--pin=${PINVALUE}")
echo

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
echo "Test"
echo "======================================================="
echo "pkcs11-tool test not working for now"
#$PKCS11_TOOL "${PRIV_ARGS[@]}" --test | grep " errors"
#assert $? "Failed running tests"

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

        METHOD="$METHOD-PSS"
        # -PSS methods should work on data > 512 bytes; generate data:
        head -c 1024 </dev/urandom > data
        if [[ "$HASH" == "SHA512" ]]; then
            continue; # This one is broken
        fi

        echo
        echo "-------------------------------------------------------"
        echo " ▸ $METHOD: Sign & Verify (KEY $SIGN_KEY)"
        echo "-------------------------------------------------------"
        if [[ -z $HASH ]]; then
            # hashing is done outside of the module. We choose here SHA256
            openssl dgst -binary -sha256 data > data.hash
            HASH_ALGORITM="--hash-algorithm=SHA256"
            VERIFY_DGEST="-sha256"
            VERIFY_OPTS="-sigopt rsa_mgf1_md:sha256"
        else
            # hashing is done inside of the module
            cp data data.hash
            HASH_ALGORITM=""
            VERIFY_DGEST="-${HASH,,*}"
            VERIFY_OPTS="-sigopt rsa_mgf1_md:${HASH,,*}"
        fi
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --id $SIGN_KEY -s -m $METHOD $HASH_ALGORITM --salt-len=-1 \
               --input-file data.hash --output-file data.sig
        assert $? "Failed to Sign data"

        # OpenSSL verification
        echo -n "Verification by OpenSSL: "
        openssl dgst -keyform PEM -verify ${TOKDIR}/$SIGN_KEY.pub $VERIFY_DGEST \
               -sigopt rsa_padding_mode:pss  $VERIFY_OPTS -sigopt rsa_pss_saltlen:-1 \
               -signature data.sig data
        if [[ "$RETOSSL" == "0" ]]; then
            assert $? "Failed to Verify signature using openssl"
        elif [[ "$?" == "0" ]]; then
            assert 1 "Unexpectedly Verified signature using OpenSSL"
        fi

        # pkcs11-tool verification
        echo "Verification by pkcs11-tool:"
        $PKCS11_TOOL "${PUB_ARGS[@]}" --id $SIGN_KEY --verify -m $METHOD \
               $HASH_ALGORITM --salt-len=-1 \
               --input-file data.hash --signature-file data.sig
        assert $? "Failed to Verify signature using pkcs11-tool"
        rm data.{sig,hash}
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

head -c 64 </dev/urandom > data
METHOD="RSA-PKCS-OAEP"
for ENC_KEY in "0001" "0002"; do
    echo
    echo "-------------------------------------------------------"
    echo " ▸ $METHOD: Decrypt (KEY $ENC_KEY)"
    echo "-------------------------------------------------------"
    # OpenSSL Encryption
    openssl pkeyutl -encrypt -inkey ${TOKDIR}/$ENC_KEY.pub -pubin -pkeyopt pad-mode:oaep -pkeyopt digest:sha512 -pkeyopt mgf1-digest:sha512 \
                -in data  -out data.crypt
    assert $? "Failed to encrypt data using OpenSSL"
    
    echo "Decryption by pkcs11-tool:"
    echo "Not working yet"
    # TODO: Failing with CKR_DEVICE_ERROR
    #$PKCS11_TOOL "${PRIV_ARGS[@]}" --id $ENC_KEY --decrypt \
    #        -m "RSA-PKCS-OAEP" --hash-algorithm "SHA256" --mgf "MGF1-SHA256" \
    #        --input-file data.crypt > data.decrypted
    #assert $? "Failed to Decrypt data"
    #diff data{,.decrypted}
    #assert $? "The decrypted data do not match the original"
    #rm data.{crypt,decrypted}
    #echo "Decryption is valid"
done
rm data
echo

echo "======================================================="
echo "Test key-pair with CKA_ALLOWED_MECHANISMS"
echo "======================================================="
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


echo "======================================================="
echo "Clean"
echo "======================================================="
rm -fr "${TMPPDIR}"
sleep 1

exit $ERRORS
