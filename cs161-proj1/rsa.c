#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <gmp.h>

#include "rsa.h"

/* Initialize a struct rsa_key. You need to do this before calling any other
 * rsa_key_* functions. Call rsa_key_clear to deallocate memory again. */
void rsa_key_init(struct rsa_key *key)
{
	mpz_init(key->d);
	mpz_init(key->e);
	mpz_init(key->n);
}

/* Free the memory used by a struct rsa_key. */
void rsa_key_clear(struct rsa_key *key)
{
	mpz_clear(key->d);
	mpz_clear(key->e);
	mpz_clear(key->n);
}

/* Read a key from the given FILE pointer. The format of a key file is
 *   d <positive integer>
 *   e <positive integer>
 *   n <positive integer>
 * The "d" line may be omitted for a public key. This is a primitive function
 * that doesn't impose any restraints on the presence of "d", "e", and "n". See
 * rsa_key_load_private and rsa_load_key_public for functions that check these
 * contraints. The return value is -1 if there was an error; 0 otherwise. */
int rsa_key_read(FILE *fp, struct rsa_key *key)
{
	mpz_t value;

	mpz_init(value);
	for (;;) {
		char c;
		mpz_t *target;
		int rc;

		rc = gmp_fscanf(fp, "%c %Zd\n", &c, value);
		if (rc == EOF)
			break;
		if (rc != 2)
			goto fail;

		switch (c) {
		case 'd':
			target = &key->d;
			break;
		case 'e':
			target = &key->e;
			break;
		case 'n':
			target = &key->n;
			break;
		default:
			/* Hmm, what variable was this supposed to be? */
			goto fail;
		}

		/* Has this variable already been assigned? */
		if (mpz_sgn(*target) > 0)
			goto fail;
		/* Make sure the value is positive. */
		if (mpz_sgn(value) <= 0)
			goto fail;

		mpz_set(*target, value);
	}

	mpz_clear(value);

	return 0;

fail:
	mpz_clear(value);
	return -1;
}

/* Write a key to the given FILE pointer. If the key is a private key (signified
 * by key->d > 0), then write the "d", "e", and "n" lines. Otherwise, write only
 * the "e", and "n" lines. Returns the number of bytes written, or -1 on
 * error. */
int rsa_key_write(FILE *fp, const struct rsa_key *key)
{
	const struct {
		char c;
		const mpz_t *value;
	} lines[] = {
		{'d', &key->d},
		{'e', &key->e},
		{'n', &key->n},
	};
	unsigned int i;
	int num_bytes;

	num_bytes = 0;
	for (i = 0; i < sizeof(lines)/sizeof(*lines); i++) {
		int rc;

		/* If this is a public key (d==0), omit the "d" line. */
		if (lines[i].c == 'd' && mpz_sgn(*lines[i].value) <= 0)
			continue;

		rc = gmp_fprintf(fp, "%c %Zd\n", lines[i].c, *lines[i].value);
		if (rc == -1)
			return -1;
		num_bytes += rc;
	}

	return num_bytes;
}

/* This function wraps rsa_key_read to read from a named file. Returns -1 on
 * error, 0 otherwise. */
static int rsa_key_load(const char *filename, struct rsa_key *key)
{
	FILE *fp;
	int rc;

	fp = fopen(filename, "rb");
	if (fp == NULL)
		return -1;
	rc = rsa_key_read(fp, key);
	if (rc != 0) {
		fclose(fp);
		return rc;
	}

	return fclose(fp);
}

/* Load a private key from a file. This function calls rsa_key_read and then
 * checks that d, e, and n are all positive. */
int rsa_key_load_private(const char *filename, struct rsa_key *key)
{
	int rc;

	rc = rsa_key_load(filename, key);
	if (rc != 0)
		return rc;
	/* A private key needs d, e, and n. */
	if (mpz_sgn(key->d) <= 0 || mpz_sgn(key->e) <= 0 || mpz_sgn(key->n) <= 0)
		return -1;

	return 0;
}

/* Load a private key from a file. This function calls rsa_key_read and then
 * checks that e and n are both positive. d may be present or not. */
int rsa_key_load_public(const char *filename, struct rsa_key *key)
{
	int rc;

	rc = rsa_key_load(filename, key);
	if (rc != 0)
		return rc;
	/* A public key needs only e and n. */
	if (mpz_sgn(key->e) <= 0 || mpz_sgn(key->n) <= 0)
		return -1;

	return 0;
}

/* Compute the encryption of m under the given key and store the result in c.
 * c = m^e mod n */
void rsa_encrypt(mpz_t c, const mpz_t m, const struct rsa_key *key)
{
	mpz_powm(c, m, key->e, key->n);
	/* TODO */
}

/* Compute the decryption of c under the given key and store the result in m.
 * m = c^d mod n */
void rsa_decrypt(mpz_t m, const mpz_t c, const struct rsa_key *key)
{
	//gmp_printf("Key: %Zd", key->e);
	mpz_powm(m, c, key->d, key->n);
	/* TODO */
}

/* Generate a random probable prime. numbits must be a multiple of 8 (i.e., a
 * round number of bytes). The base-2 logarithm of the result will lie in the
 * interval [numbits - 0.5, numbits). Calls abort if any error occurs. */
static void generate_prime(mpz_t p, unsigned int numbits)
{
	//Check if numbits is devisible by 8
	if(!((numbits % 8) == 0)) {
		printf("Error: Cannot generate prime of %d bits (must be multiple of 8)", numbits);
		abort();
	}

	//Allocate array to read into
	unsigned int num_bytes = numbits / 8;	
	char *rand_array = malloc(num_bytes);
	if(rand_array == NULL) {
		printf("Unable to allocate array for prime generation\n");
		abort();
	}

	//Open dev/urandom
	FILE *rand_data;
	rand_data = fopen("/dev/urandom", "r");

	//Init prime test var
	int prime_test = 0;
	
	//While our number is not prime, read more from urandom and generate new numbers
	while(!((prime_test == 2) || (prime_test == 1))) {


		size_t result = fread(rand_array, 1, num_bytes, rand_data);

		if((int) result != (int) num_bytes) {
			printf("Error: Could not read %d bits from dev/random", num_bytes);
			printf("Result: %d, Numbits: %d",(int) result, numbits);
			abort();
		}

		*(rand_array) = *(rand_array) | 0xc0;

		//Copy to mpz var
		mpz_import(p, num_bytes, 1, sizeof(*(rand_array)), 0, 0, rand_array);
		//Test for primality
		prime_test = mpz_probab_prime_p(p, 25);
	}

	//Prime found, clean up
	free(rand_array);
	fclose(rand_data);
	//mpz_clear(rand_num)



	//*(rand_data) = *(rand_data) | 0xc0;



	/* TODO */
}

/* Generate an RSA key. The base-2 logarithm of the modulus n will lie in the
 * interval [numbits - 1, numbits). Calls abort if any error occurs. */
void rsa_genkey(struct rsa_key *key, unsigned int numbits)
{
	//Init our mpz vars 
	mpz_t p, q, n, pq, d, e;
	mpz_init(pq);
	mpz_init(d);
	mpz_init(e);
	mpz_init(n);
	mpz_init(p);
	mpz_init(q);

	//Generate two primes and make sure they are different
	int cmp = 0
	while(cmp == 0) {
		generate_prime(p, numbits/2);
		generate_prime(q, numbits/2);
		cmp = mpz_cmp(p, q);
	}

	//Generate n as the product of p and q
	mpz_mul(n, p, q);

	mpz_sub_ui(p, p, 1);
	mpz_sub_ui(q, q, 1);
	mpz_mul(pq, p, q);

	mpz_set_ui(e, 65537);
	mpz_invert(d, e, pq);

	mpz_set(key->d, d);
	mpz_set(key->e, e);
	mpz_set(key->n, n);

	mpz_clear(d);
	mpz_clear(e);
	mpz_clear(n);
	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(pq);
	//MAKE SURE NOT THE SAME??


	/* TODO */
}
