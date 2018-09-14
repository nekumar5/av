#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#define ERR(x, ...)	fprintf(stderr, "%s:%d " x "\n", __FILE__, __LINE__, ##__VA_ARGS__)

int
main(int argc, char **argv)
{
	struct eng_cmd *post_cmds;
	int post_num, failure = 0, i;
	ENGINE *e;
	EVP_PKEY *key;
   const char *engine_id = "swims";

	if (!argv[1]) {
		fprintf(stderr, "usage: %s: <swims key file>\n", argv[0]);
		return -1;
	}

   ENGINE_load_builtin_engines();

	e = ENGINE_by_id(engine_id);
	if (!e) {
		/* the engine isn't available */
		ERR_print_errors_fp(stderr);
		ERR("ENGINE_by_id failed.");
		return 1;
	}

	if (!ENGINE_init(e)) {
		/* the engine couldn't initialise, release 'e' */
		ERR_print_errors_fp(stderr);
		ERR("ENGINE_init failed.");
		ENGINE_free(e);
		ENGINE_finish(e);
		return 2;
	}
	if (!ENGINE_set_default_RSA(e) || !ENGINE_set_default_RAND(e)) {
		/* This should only happen when 'e' can't initialise, but the previous
		 * statement suggests it did. */
		ERR_print_errors_fp(stderr);
		ERR("ENGINE_init failed.");
		ENGINE_free(e);
		ENGINE_finish(e);
		return 3;
	}

	/* ENGINE_init() returned a functional reference, so free the */
	/* structural reference with ENGINE_free */
	ENGINE_free(e);

	if ((key = ENGINE_load_private_key(e, argv[1], NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		ERR("Couldn't load SWIMS key \"%s\".", argv[1]);
		return 4;
	}

	/* Release the functional reference from ENGINE_init() */
	ENGINE_finish(e);
	e = NULL;

	return failure ? 1 : 0;
}
