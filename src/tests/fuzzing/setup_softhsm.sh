echo "directories.tokendir = .tokens/" > .softhsm2.conf
if [ -d ".tokens" ]; then
       mkdir ".tokens"
fi
export SOFTHSM2_CONF=".softhsm2.conf"
$1 --init-token --slot 0 --label "SC test" --so-pin=12345678 --pin=123456
