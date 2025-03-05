#!/bin/bash -e

ERRORS=0
function assert() {
	if [[ $1 != 0 ]]; then
		echo "====> ERROR: $2"
		ERRORS=ERRORS + 1
	fi
}

function clean() {
	heading "Clean"
	rm -fr "${TMPPDIR}"
}

function heading() {
	echo
	echo "======================================================="
	echo "$1"
	echo "======================================================="	
}

function subheading() {
	echo
	echo "-------------------------------------------------------"
	echo " > $1"
	echo "-------------------------------------------------------"
}

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

function test_rsa_pkcs_sign_verify() {
	HASH="$1"
	SIGN_KEY="$2"
	METHOD="RSA-PKCS"

	subheading "$METHOD: Sign & Verify (KEY $SIGN_KEY)"

	# RSA-PKCS works only on small data - generate small data:
	head -c 64 </dev/urandom > data
	if [[ ! -z $HASH ]]; then
		METHOD="$HASH-$METHOD"
		# hash- methods should work on data > 512 bytes
		head -c 1024 </dev/urandom > data
	fi

	# pkcs11-tool signature
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
	assert $? "Failed to Verify signature using OpenSSL"

	# pkcs11-tool verification
	echo "Verification by pkcs11-tool:"
	$PKCS11_TOOL "${PUB_ARGS[@]}" --id $SIGN_KEY --verify -m $METHOD \
			--input-file data --signature-file data.sig
	assert $? "Failed to Verify signature using pkcs11-tool"
	rm data.sig data
}

function test_rsa_pkcs_pss_sign_verify() {
	HASH="$1"
	SIGN_KEY="$2"
	METHOD="RSA-PKCS"

	subheading "$METHOD: Sign & Verify (KEY $SIGN_KEY)"

	if [[ ! -z $HASH ]]; then
		METHOD="$HASH-$METHOD"
	fi
	METHOD="$METHOD-PSS"
	# -PSS methods should work on data > 512 bytes; generate data:
	head -c 1024 </dev/urandom > data

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

	# pkcs11-tool signature
	$PKCS11_TOOL "${PRIV_ARGS[@]}" --id $SIGN_KEY -s -m $METHOD $HASH_ALGORITM --salt-len=-1 \
			--input-file data.hash --output-file data.sig
	assert $? "Failed to Sign data"

	# OpenSSL verification
	echo -n "Verification by OpenSSL: "
	openssl dgst -keyform PEM -verify ${TOKDIR}/$SIGN_KEY.pub $VERIFY_DGEST \
			-sigopt rsa_padding_mode:pss  $VERIFY_OPTS -sigopt rsa_pss_saltlen:-1 \
			-signature data.sig data
	assert $? "Failed to Verify signature using openssl"

	# pkcs11-tool verification
	echo "Verification by pkcs11-tool:"
	$PKCS11_TOOL "${PUB_ARGS[@]}" --id $SIGN_KEY --verify -m $METHOD \
			$HASH_ALGORITM --salt-len=-1 \
			--input-file data.hash --signature-file data.sig
	assert $? "Failed to Verify signature using pkcs11-tool"
	rm data.{sig,hash} data
}

function test_ecdsa_sign_verify() {
	SIGN_KEY="$1"
    METHOD="ECDSA"

    subheading "$METHOD: Sign & Verify (KEY $SIGN_KEY)"

	head -c 1024 </dev/urandom > data
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
    rm data.sig{,.openssl} data.hash data
}

function test_rsa_pkcs_decrypt() {
	ENC_KEY="$1"
	METHOD="RSA-PKCS"
    
    echo
    
    subheading "$METHOD: Decrypt (KEY $ENC_KEY)"

	head -c 64 </dev/urandom > data
    # OpenSSL Encryption
    openssl pkeyutl -encrypt -inkey ${TOKDIR}/$ENC_KEY.pub -in data -pubin -out data.crypt
    assert $? "Failed to encrypt data using OpenSSL"
    # pkcs11-tool Decryption
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --id $ENC_KEY --decrypt -m $METHOD \
            --input-file data.crypt > data.decrypted
    assert $? "Failed to Decrypt data"
    diff data{,.decrypted}
    assert $? "The decrypted data do not match the original"
    rm data.{crypt,decrypted} data
    echo "Decryption is valid"
}

function test_import_key() {
	KEYTYPE="$1"

    subheading "Generate and import $KEYTYPE keys"
    
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
}
