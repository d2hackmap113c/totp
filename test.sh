
TOTP="tcc -run totp.c"
#TOTP="/git/tcc.sh totp.c"
$TOTP gmt
$TOTP valid
echo -n "website1:"
$TOTP ONSWG4TFOQYDAMBR 
echo -n "website2:"
$TOTP ONSWG4TFOQYDAMBS
