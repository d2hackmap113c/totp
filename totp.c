#include <stdio.h>
#include <time.h>
#include <string.h>

#define SHA1HashSize 20
#define FLAG_CORRUPTED  2
struct sha1 {
  uint8_t  sha1buf[64];       /* 512-bit message blocks         */
  uint32_t sha1hash[5];    /* Message Digest                 */
  uint32_t Length_Low;              /* Message length in bits         */
  uint32_t Length_High;             /* Message length in bits         */
  uint16_t sha1buflen;     /* Index into message block array */
  uint8_t  done;
};
int sha1_reset (struct sha1* context);
int sha1_input (struct sha1* context, const uint8_t* inData, unsigned length);
int sha1_result(struct sha1* context, uint8_t Message_Digest[SHA1HashSize]);
static uint32_t _circular_shift(const uint32_t nbits, const uint32_t word) {
  return ((word << nbits) | (word >> (32 - nbits)));
}
int sha1_reset(struct sha1* context) {
  if (context == 0) return -1;
  context->Length_Low=0;
  context->Length_High=0;
  context->sha1buflen=0;
  context->sha1hash[0] = 0x67452301;
  context->sha1hash[1] = 0xEFCDAB89;
  context->sha1hash[2] = 0x98BADCFE;
  context->sha1hash[3] = 0x10325476;
  context->sha1hash[4] = 0xC3D2E1F0;
  context->done = 0;
  return 0;
}
void _process_block(struct sha1 *context) {
	const uint32_t K[]={0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xCA62C1D6};
	uint8_t       t;                 /* Loop counter                */
	uint32_t      temp;              /* Temporary word value        */
	uint32_t      W[80];             /* Word sequence               */
	uint32_t      A, B, C, D, E;     /* Word buffers                */
	for (int t = 0; t < 16; ++t) {
		W[t]  = ((uint32_t)context->sha1buf[t * 4 + 0]) << 24;
		W[t] |= ((uint32_t)context->sha1buf[t * 4 + 1]) << 16;
		W[t] |= ((uint32_t)context->sha1buf[t * 4 + 2]) << 8;
		W[t] |= ((uint32_t)context->sha1buf[t * 4 + 3]) << 0;
	}
	for (int t = 16; t < 80; ++t) W[t] = _circular_shift(1, (W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]));
	A = context->sha1hash[0];
	B = context->sha1hash[1];
	C = context->sha1hash[2];
	D = context->sha1hash[3];
	E = context->sha1hash[4];
	for (int t = 0; t < 20; ++t) {
		temp =  _circular_shift(5, A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
		E = D; D = C; C = _circular_shift(30, B); B = A; A = temp;
	}
	for (int t = 20; t < 40; ++t) {
		temp = _circular_shift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
		E = D; D = C; C = _circular_shift(30, B); B = A; A = temp;
	}
	for (int t = 40; t < 60; ++t) {
		temp = _circular_shift(5, A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
		E = D; D = C; C = _circular_shift(30, B); B = A; A = temp;
	}
	for (int t = 60; t < 80; ++t) {
		temp = _circular_shift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
		E = D; D = C; C = _circular_shift(30, B); B = A; A = temp;
	}
	context->sha1hash[0] += A;
	context->sha1hash[1] += B;
	context->sha1hash[2] += C;
	context->sha1hash[3] += D;
	context->sha1hash[4] += E;
	context->sha1buflen = 0;
}
int sha1_input(struct sha1* context, const uint8_t* inData, unsigned length) {
  if (length == 0) return 0;
  if (!context||!inData) return -1;
  if (context->done) sha1_reset(context);
  while (length) {
    context->sha1buf[context->sha1buflen++] = *inData++;
    context->Length_Low+=8;
    if (context->Length_Low==0) context->Length_High++;
    if (context->sha1buflen==64) _process_block(context);
    length--;
  }
  return 0;
}
int sha1_result(struct sha1* context, uint8_t Message_Digest[SHA1HashSize]) {
  int i;
  if (!context||!Message_Digest) return -1;
  if (!context->done) {
		if (context->sha1buflen > 55) {
			context->sha1buf[context->sha1buflen++] = 0x80;
			while (context->sha1buflen < 64) context->sha1buf[context->sha1buflen++] = 0;
			_process_block(context);
			while (context->sha1buflen < 56) context->sha1buf[context->sha1buflen++] = 0;
		} else {
			context->sha1buf[context->sha1buflen++] = 0x80;
			while (context->sha1buflen < 56) context->sha1buf[context->sha1buflen++] = 0;
		}
		context->sha1buf[56] = context->Length_High >> 24;
		context->sha1buf[57] = context->Length_High >> 16;
		context->sha1buf[58] = context->Length_High >>  8;
		context->sha1buf[59] = context->Length_High >>  0;
		context->sha1buf[60] = context->Length_Low  >> 24;
		context->sha1buf[61] = context->Length_Low  >> 16;
		context->sha1buf[62] = context->Length_Low  >>  8;
		context->sha1buf[63] = context->Length_Low  >>  0;
		_process_block(context);
    for (i=0;i<64;++i) context->sha1buf[i] = 0;
    context->Length_Low=0;context->Length_High=0;
    context->done=1;
  }
  for (i=0;i<SHA1HashSize;++i)
    Message_Digest[i] = (context->sha1hash[i>>2]>>(8 * (3 - (i & 0x03))));
  return 0;
}
#define HMAC_SHA1_DIGEST_SIZE 20
#define HMAC_SHA1_BLOCK_SIZE  64
void hmac_sha1(const uint8_t* key, uint32_t keysize, const uint8_t* msg, uint32_t msgsize, uint8_t* output) {
  struct sha1 outer, inner;
  uint8_t tmp;
  if (keysize > HMAC_SHA1_BLOCK_SIZE) {
    uint8_t new_key[HMAC_SHA1_DIGEST_SIZE];
    sha1_reset(&outer);
    sha1_input(&outer, key, keysize);
    sha1_result(&outer, new_key);
    return hmac_sha1(new_key, HMAC_SHA1_DIGEST_SIZE, msg, msgsize, output);
  } 
  sha1_reset(&outer);
  sha1_reset(&inner);
  int i;
  for (i = 0; i < keysize; ++i) {
    tmp=key[i]^0x5C;sha1_input(&outer, &tmp, 1);
    tmp=key[i]^0x36;sha1_input(&inner, &tmp, 1);
  }
  for (; i < HMAC_SHA1_BLOCK_SIZE; ++i) {
    tmp=0x5C;sha1_input(&outer, &tmp, 1);
    tmp=0x36;sha1_input(&inner, &tmp, 1);
  }
  sha1_input(&inner, msg, msgsize);
  sha1_result(&inner, output);
  sha1_input(&outer, output, HMAC_SHA1_DIGEST_SIZE);
  sha1_result(&outer, output);
}
int encodeBase32(char* inputBuf, int inputLen, char *outputBuf, int usePadding) {
  char base32StandardAlphabet[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"};
  char standardPaddingChar = '='; 
  int outputLen = 0,count = 0,bufSize = 8,index = 0;
  if (inputLen < 0 || inputLen > 268435456LL) return 0;
  if (inputLen > 0) {
    int buffer=inputBuf[0],next = 1,bitsLeft = 8;
    while (count < bufSize && (bitsLeft > 0 || next < inputLen)) {
      if (bitsLeft < 5) {
        if (next < inputLen) {
          buffer<<=8;buffer|=inputBuf[next] & 0xFF;
          next++;bitsLeft+=8;
        } else {
          int pad=5-bitsLeft;buffer<<=pad;bitsLeft+=pad;
        }
      }
      index = 0x1F & (buffer >> (bitsLeft -5));
      bitsLeft -= 5;
      outputBuf[outputLen++] = base32StandardAlphabet[index];
    }
  }
  if (usePadding) {
    int pads=outputLen%8;
    if (pads) {pads=8-pads;for (int i=0;i<pads;i++) outputBuf[outputLen++]=standardPaddingChar;}
  }
  return outputLen;
}
int decodeBase32(char* inputBuf, int inputLen, char *outputBuf) {
  int outputLen=0,bits=0,nbits=0;
  for (int i = 0; i < inputLen; i++) {
    char ch = inputBuf[i];
    // ignoring some characters: ' ', '\t', '\r', '\n', '='
    if (ch == 0xA0 || ch == 0x09 || ch == 0x0A || ch == 0x0D || ch == 0x3D) continue;
    // recovering mistyped: '0' -> 'O', '1' -> 'L', '8' -> 'B'
    if (ch == 0x30) { ch = 0x4F; } else if (ch == 0x31) { ch = 0x4C; } else if (ch == 0x38) { ch = 0x42; }
    // look up one base32 symbols: from 'A' to 'Z' or from 'a' to 'z' or from '2' to '7'
    if ((ch >= 0x41 && ch <= 0x5A) || (ch >= 0x61 && ch <= 0x7A)) { ch = ((ch & 0x1F) - 1); }
    else if (ch >= 0x32 && ch <= 0x37) { ch -= (0x32 - 26); }
    else return 0;
    bits<<=5;bits|=ch;nbits+=5;
    if (nbits>=8) {nbits-=8;outputBuf[outputLen++]=bits>>nbits;}
  }
  return outputLen;
}
void showtime(time_t t) {
	struct tm *m=gmtime(&t);
	if (!m) return;
	printf("GMT time: %d-%d-%d %02d:%02d:%02d\n",1900+m->tm_year,m->tm_mon+1,m->tm_mday,
		m->tm_hour,m->tm_min,m->tm_sec);
}
int totp_base32(char *base32secret,int digits,time_t t) {
	static int DIGITS_POWER[]={1,10,100,1000,10000,100000,1000000,10000000,100000000};
	char secret[128],stepHex[8],hash[SHA1HashSize];
	int secretLen=decodeBase32(base32secret,strlen(base32secret),secret);
	time_t steps=t/30;
	for (int i=7;i>=0;i--) {stepHex[i]=steps&0xFF;steps>>=8;}
	hmac_sha1(secret,secretLen,stepHex,8,hash);
	int offset=hash[SHA1HashSize - 1] & 0xf;
	int binary=((hash[offset]&0x7f)<<24)|((hash[offset+1]&0xff)<<16)|
		((hash[offset+2]&0xff)<<8)|(hash[offset+3]&0xff);
	return binary%DIGITS_POWER[digits];
}
void rf6238test() {
	char *base32secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
	int testTime[]={59,1111111109,1111111111,1234567890,2000000000};
	int answer[]={94287082,7081804,14050471,89005924,69279037};
	for (int i=0;i<5;i++) {
		int t=testTime[i];
		int d=totp_base32(base32secret,8,t);
		printf("%d\t%08d\t%08d\n",t,d,answer[i]);
		if (d!=answer[i]) {printf("Test Error\n");return;}
	}
	printf("OK\n");
}
int main(int argc,char *argv[]) {
	if (argc<2) {
		printf("%s gmt        - show GMT time (time zone 0)\n",argv[0]);
		printf("%s valid      - show how many seconds left for the generated key\n",argv[0]);
		printf("%s <secret>   - show 6 digit key generated by base32 encoded secret and GMT time(RFC6238)\n",argv[0]);
		return 0;
	}
	char *secret=argv[1];
	if (strcmp(secret,"gmt")==0) {
		showtime(time(0));
	} else if (strcmp(secret,"valid")==0) {
		time_t t=time(0);
		printf("valid in %d seconds\n",30-(t%30));
	} else if (strcmp(secret,"test")==0) {
		rf6238test();
	} else {
		printf("%06d\n",totp_base32(secret,6,time(0)));
	}
	return 0;
}
