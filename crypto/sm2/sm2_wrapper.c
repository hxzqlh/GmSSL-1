#include <openssl/sm2.h>

EC_GROUP *new_ec_group(int is_prime_field,
	const char *p_hex, const char *a_hex, const char *b_hex,
	const char *x_hex, const char *y_hex, const char *n_hex, const char *h_hex)
{
	int ok = 0;
	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *p = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	EC_POINT *G = NULL;
	point_conversion_form_t form = SM2_DEFAULT_POINT_CONVERSION_FORM;
	int flag = 0;

	if (!(ctx = BN_CTX_new())) {
		goto err;
	}

	if (!BN_hex2bn(&p, p_hex) ||
	    !BN_hex2bn(&a, a_hex) ||
	    !BN_hex2bn(&b, b_hex) ||
	    !BN_hex2bn(&x, x_hex) ||
	    !BN_hex2bn(&y, y_hex) ||
	    !BN_hex2bn(&n, n_hex) ||
	    !BN_hex2bn(&h, h_hex)) {
		goto err;
	}

	if (is_prime_field) {
		if (!(group = EC_GROUP_new_curve_GFp(p, a, b, ctx))) {
			goto err;
		}
		if (!(G = EC_POINT_new(group))) {
			goto err;
		}
		if (!EC_POINT_set_affine_coordinates_GFp(group, G, x, y, ctx)) {
			goto err;
		}
	} else {
		goto err;
	}

	if (!EC_GROUP_set_generator(group, G, n, h)) {
		goto err;
	}

	EC_GROUP_set_asn1_flag(group, flag);
	EC_GROUP_set_point_conversion_form(group, form);

	ok = 1;
err:
	BN_CTX_free(ctx);
	BN_free(p);
	BN_free(a);
	BN_free(b);
	BN_free(x);
	BN_free(y);
	BN_free(n);
	BN_free(h);
	EC_POINT_free(G);
	if (!ok && group) {
		ERR_print_errors_fp(stderr);
		EC_GROUP_free(group);
		group = NULL;
	}

	return group;
}

EC_GROUP* ec_group()
{
    EC_GROUP* group = new_ec_group(
        1,
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",     //  p
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",     //  a
        "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",     //  b
        "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",     //  x
        "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",     //  y
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",     //  n
        "1");
    OPENSSL_assert(group);
    return group;
}

EC_KEY *new_ec_key(const EC_GROUP *group, const unsigned char *sk, int len)
{
	int ok = 0;
	EC_KEY *ec_key = NULL;
	BIGNUM *d = NULL;

	OPENSSL_assert(group);

	if (!(ec_key = EC_KEY_new())) {
		goto end;
	}
	if (!EC_KEY_set_group(ec_key, group)) {
		goto end;
	}

	if (sk) {
	    d = BN_new();
		if (!BN_bin2bn(sk, len, d)) {
			goto end;
		}
		if (!EC_KEY_set_private_key(ec_key, d)) {
			goto end;
		}
	}

	if (!EC_KEY_generate_key(ec_key)) {
	    goto end;
	}

	ok = 1;
end:
	if (d) BN_free(d);
	if (!ok && ec_key) {
		ERR_print_errors_fp(stderr);
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}
	return ec_key;
}

void sm2_generate_key(const EC_GROUP* group, unsigned char *ucpPrivateKey, unsigned char *ucpPublicKey)
{
    OPENSSL_assert(group);
    if (ucpPrivateKey == NULL || ucpPublicKey == NULL) {
        return;
    }

    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    EC_KEY *ec_key = NULL;
    BN_CTX *ctx = NULL;

    do {
        x = BN_new();
        y = BN_new();
        ec_key = new_ec_key(group, NULL, 0);
        BN_bn2bin(EC_KEY_get0_private_key(ec_key), ucpPrivateKey);
        EC_POINT_get_affine_coordinates_GFp(group, EC_KEY_get0_public_key(ec_key), x, y, ctx);
        BN_bn2bin(x, ucpPublicKey);
        BN_bn2bin(y, ucpPublicKey+32);
    } while(0);

    if(x) BN_free(x);
    if(y) BN_free(y);
    if(ec_key) EC_KEY_free(ec_key);
    if(ctx) BN_CTX_free(ctx);
}

void sm2_pubkey_from_privkey(const EC_GROUP* group, const unsigned char* ucpPrivateKey, unsigned char* ucpPublicKey)
{
    OPENSSL_assert(group);
    if (ucpPrivateKey == NULL || ucpPublicKey == NULL) {
        return;
    }

    BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	EC_KEY *ec_key = NULL;
	BN_CTX *ctx = NULL;

    do {
        x = BN_new();
        y = BN_new();
        ec_key = new_ec_key(group, ucpPrivateKey, 32);
        ctx = BN_CTX_new();
        //EC_KEY_get0_public_key(ec_key);
        EC_POINT_get_affine_coordinates_GFp(group, EC_KEY_get0_public_key(ec_key), x, y, ctx);
        BN_bn2bin(x, ucpPublicKey);
        BN_bn2bin(y, ucpPublicKey+32);
    } while(0);

    if(x) BN_free(x);
    if(y) BN_free(y);
    if(ec_key) EC_KEY_free(ec_key);
    if(ctx) BN_CTX_free(ctx);
}

void sm2_sign(EC_GROUP* group, unsigned char* ucpPrivateKey, unsigned char* ucpMessage, unsigned char* ucpSignature)
{
    OPENSSL_assert(group);
    if (ucpPrivateKey == NULL || ucpMessage == NULL || ucpSignature == NULL) {
        return;
    }

    EC_KEY *ec_key = NULL;
    BIGNUM *d = NULL;

    unsigned int ilenSignature = 65;
    unsigned int ilenMessage = 32;
    unsigned int ilenPrivateKey = 32;
    int v = 0;

    do {
        ec_key = EC_KEY_new();
        d = BN_new();
        EC_KEY_set_group(ec_key, group);
        BN_bin2bn(ucpPrivateKey, ilenPrivateKey, d);
        EC_KEY_set_private_key(ec_key, d);
        if (!SM2_sign_v(ucpMessage, ilenMessage, ucpSignature + 1, &ilenSignature, &v, ec_key)) {
            return;
        }
        ucpSignature[0] = v + 0x1B;
    } while(0);

    if(ec_key) EC_KEY_free(ec_key);
    if(d) BN_free(d);
}

int sm2_recover(EC_GROUP* group, unsigned char* ucpSignature, unsigned char* ucpMessage, unsigned char* ucpPublicKey)
{
    OPENSSL_assert(group);
    if (ucpSignature == NULL || ucpMessage == NULL || ucpPublicKey == NULL) {
        return -1;
    }

    int ilenMessage = 32;
    int ilenPublicKey = 64;
    int v = ucpSignature[0] - 0x1B;

    return SM2_recover(group, ucpMessage, ilenMessage, ucpSignature + 1, 64, v, ucpPublicKey, &ilenPublicKey);
}
