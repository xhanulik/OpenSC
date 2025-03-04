#!/bin/bash -e

PUB_ARGS=("--module=${P11LIB}" "--token-label=${TOKENLABEL}")
PRIV_ARGS=("${PUB_ARGS[@]}" "--login" "--pin=${PINVALUE}")

ERRORS=0
function assert() {
	if [[ $1 != 0 ]]; then
		echo "====> ERROR: $2"
		ERRORS=ERRORS + 1
	fi
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
