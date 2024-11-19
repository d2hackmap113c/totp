Time-Based One-Time Password (RFC6238)

Include HMAC-SHA1 BASE32 RFC6238 in a single C file. Test on ubuntu and Windows XP with tcc(Tiny C Compiler).

This is used as a secondary login method to certain websites like github.com. Website offers a secret key encoded with base32(with characters A-Z and 2-7). totp.c takes the secret as an argument and print out 6 digits key based on GMT time.

If the website only offers QR-code, save the QR-code image using the PrtSc key. Then install the zbar-tools package. Find out the secret using the command 'zbarimg <qr.png>'.

Sample script to use totp.c:
--- test.sh ---
TOTP="tcc -run totp.c"
#print GMT time (need to be corret in order to successfully login)
$TOTP gmt
#print out remaining valid second for the key
$TOTP valid
#website1 key
echo -n "website1:"
$TOTP ONSWG4TFOQYDAMBR 
#website2 key
echo -n "website2:"
$TOTP ONSWG4TFOQYDAMBS
--- end ---
