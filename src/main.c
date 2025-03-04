// Bowser Browser

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

// some defines

#define BW_STATIC_ASSERT(test) typedef char assertion_on_mystruct[( !!(test) )*2-1 ]

// vectors

typedef struct {
	uint32_t nmemb;
	uint32_t maxmemb;
	uint64_t elemsize;
} bwvecmeta_t;

#define BWVEC_MOREMEMB(old) (old * 2)
#define BWVEC_DEFAULTMAXMEMB (4)
#define BWVEC_NEW(type) bwvec_init(sizeof(type), BWVEC_DEFAULTMAXMEMB)

BW_STATIC_ASSERT(sizeof(bwvecmeta_t) == 16);

int bwvec_pushdata(void *vptr, void const *segment) {
	bwvecmeta_t *v = *(bwvecmeta_t **)vptr - 1;

	if (v->nmemb + 1 <= v->maxmemb) {
addmemb:
		memcpy(*(char **)vptr + (v->nmemb * v->elemsize),
				segment, v->elemsize);
		++v->nmemb;
		return 0;
	}
	v->maxmemb = BWVEC_MOREMEMB(v->maxmemb);
	v = realloc(v, sizeof(bwvecmeta_t) + v->elemsize * v->maxmemb);
	if (v == NULL)
		return -1;
	*(void **)vptr = v + 1;
	goto addmemb;
	return 0;
}

int bwvec_pushnum(void *vptr, __int128_t u) {
	return bwvec_pushdata(vptr, &u);
}

int bwvec_pushptr(void *vptr, void *ptr) {
	return bwvec_pushdata(vptr, &ptr);
}

void *bwvec_init(size_t elemsize, size_t maxmemb) {
	bwvecmeta_t *ptr = malloc(
		sizeof(bwvecmeta_t) +
		(elemsize * maxmemb)
	);
	if (ptr == NULL)
		return NULL;
	ptr->nmemb = 0;
	ptr->maxmemb = (uint32_t)maxmemb;
	ptr->elemsize = (uint64_t)elemsize;
	return ptr + 1;
}

void bwvec_close(void *v) {
	free((bwvecmeta_t *)v - 1);
}

size_t bwvec_size(void const *v) {
	return (size_t)((bwvecmeta_t const *)v - 1)->nmemb;
}

void bwvec_reset(void *v) {
	((bwvecmeta_t *)v - 1)->nmemb = 0;
}

int bwvec_empty(void const *v) {
	return (((bwvecmeta_t const *)v - 1)->nmemb == 0);
}

// tokenizer

typedef enum {
	TOKOPEN,	// <
	TOKCLOSE,	// >
	TOKSLASH,	// /
	TOKSYM,		// anything else
	TOKQUOTE,	// "
	TOKEQUAL, 	// =
	TOKEND,
} bw_token_t;

static bw_token_t const CHAR2TOK_MAP[] = { // a waste of memory
	['='] = TOKEQUAL,
	['/'] = TOKSLASH,
	['"'] = TOKQUOTE,
};

static char const *const TOK2STR_MAP[] = {
	[TOKOPEN] = "<",
	[TOKCLOSE] = ">",
	[TOKSLASH] = "/",
	[TOKSYM] = "TOKSYM",
	[TOKQUOTE] = "\"",
	[TOKEQUAL] = "=",
	[TOKEND] = "END"
};

typedef struct {
	bw_token_t tok;
	char *arg;
} bw_tokenarg_t;

// tokenizer

static bw_tokenarg_t *bw_gettokensfromhtml(char const *html) {
	bw_tokenarg_t *toks = BWVEC_NEW(bw_tokenarg_t);
	char *buf = BWVEC_NEW(char);
	bw_tokenarg_t tmp = { .tok = TOKEND, .arg = NULL };
	bw_token_t actual;
	bool in = false;

	if (toks == NULL)
		return NULL;
	for (; *html != '\0'; ++html) {
		actual = TOKEND;
		switch (*html) {
			case '<':
				actual = TOKOPEN;
				in = true;
				break;
			case '>':
				actual = TOKCLOSE;
				in = false;
				break;
			case '=':
			case '"':
			case '/':
				if (in)
					actual = CHAR2TOK_MAP[*html];
				else
					(void)bwvec_pushnum(&buf, *html);
				break;
			case ' ':
			case '\n':
			case '\t':
				if (in)
					actual = TOKSYM;
				else if (!bwvec_empty(buf))
					(void)bwvec_pushnum(&buf, *html);
				break;
			default:
				(void)bwvec_pushnum(&buf, *html);
				break;
		}
		if (actual == TOKEND)
			continue;
		if (!bwvec_empty(buf)) {
			tmp.arg = strndup(buf, bwvec_size(buf));
			tmp.tok = TOKSYM;
			(void)bwvec_pushdata(&toks, &tmp);
			bwvec_reset(buf);
			tmp.arg = NULL;
		}
		if (actual == TOKSYM)
			continue;
		tmp.tok = actual;
		(void)bwvec_pushdata(&toks, &tmp);
	}
	bwvec_close(buf);
	tmp.tok = TOKEND;
	(void)bwvec_pushdata(&toks, &tmp);
	return toks;
}

static int bw_getfilecontent(char **buf, char const *file) {
	int fd;
	struct stat st;

	if (buf == NULL || stat(file, &st) == -1)
		return -1;
	fd = open(file, O_RDONLY);
	if (fd == -1)
		return -1;
	*buf = malloc(st.st_size + 1);
	if (*buf == NULL) {
		close(fd);
		return -1;
	}
	if (read(fd, *buf, st.st_size) == -1) {
		free(*buf);
		close(fd);
		return -1;
	}
	(*buf)[st.st_size] = '\0';
	(void)close(fd);
	return 0;
}

static void display_tokens(bw_tokenarg_t *args) {
	for (size_t n = 0; n < bwvec_size(args); ++n) {
		printf("%s", TOK2STR_MAP[args[n].tok]);
		if (args[n].tok == TOKSYM)
			printf("(%s)", args[n].arg ? args[n].arg : "(null)");
		printf(" ");
	}
	puts("");
}

// parser

typedef struct {
	char *key;
	char *value;
} bw_htmlprop_t;

typedef struct s_bw_html {
	char *type;
	char *data;
	bw_htmlprop_t *props;
	struct s_bw_html *parent;
	struct s_bw_html **children;
} bw_html_t;

bw_html_t *bw_nodenew(char const *type) {
	bw_html_t *node = malloc(sizeof(bw_html_t));

	if (node == NULL)
		return NULL;
	if (type != NULL) {
		node->type = strdup(type);
		if (node->type == NULL) {
			free(node);
			return NULL;
		}
	} else
		node->type = NULL;
	node->children = BWVEC_NEW(bw_html_t *);
	if (node->children == NULL) {
		free(node->type);
		free(node);
		return NULL;
	}
	node->props = BWVEC_NEW(bw_htmlprop_t);
	if (node->props == NULL) {
		bwvec_close(node->children);
		free(node->type);
		free(node);
		return NULL;
	}
	node->parent = NULL;
	node->data = NULL;
	return node;
}

void bw_nodeadopt(bw_html_t *node, bw_html_t *child) {
	if (child == NULL)
		return;
	child->parent = node;
	(void)bwvec_pushptr(&node->children, child);
}

void bw_nodeclose(bw_html_t *node) {
	for (size_t n = 0; n < bwvec_size(node->props); ++n) {
		free(node->props[n].key);
		free(node->props[n].value);
	}
	bwvec_close(node->props);
	if (node->type != NULL)
		free(node->type);
	for (size_t n = 0; n < bwvec_size(node->children); ++n) {
		bw_nodeclose(node->children[n]);
	}
	bwvec_close(node->children);
	if (node->data != NULL)
		free(node->data);
	free(node);
}

// stringelem ::= TOKQUOTE TOKSYM TOKQUOTE
int bw_parsestringelem() {
	return -1;
}

// keyval ::= TOKSYM TOKEQUAL <stringelem>
int bw_parsekeyval() {
	return -1;
}

// bloc ::= TOKOPEN TOKSYM [<keyval>] TOKCLOSE
int bw_parsebloc(bw_html_t *node, bw_tokenarg_t const **toks) {
	if ((*toks)[0].tok == TOKOPEN &&
			(*toks)[1].tok == TOKSYM &&
			(*toks)[2].tok == TOKCLOSE) {
		//printf("IT WAS A BLOC %s !\n", (*toks)[1].arg);
		bw_nodeadopt(node, bw_nodenew((*toks)[1].arg));
		(*toks) += 3;
		return 0;
	}
	return -1;
}

// endbloc ::= TOKOPEN TOKSLASH TOKSYM TOKCLOSE
int bw_parseendbloc(bw_html_t *node, bw_tokenarg_t const **toks) {
	if ((*toks)[0].tok == TOKOPEN &&
			(*toks)[1].tok == TOKSLASH &&
			(*toks)[2].tok == TOKSYM &&
			(*toks)[3].tok == TOKCLOSE) {
		//printf("IT WAS A END BLOC OF %s !\n", (*toks)[2].arg);
		(*toks) += 4;
		return 0;
	}
	return -1;
}

// something ::= TOKSYM | <endbloc> | <bloc>
int bw_parsesomething(bw_html_t *node, bw_tokenarg_t const **toks) {
	//printf("IM IN %s...\n", node->type ? node->type : "root");
	if ((**toks).tok == TOKEND)
		return 0;
	if ((**toks).tok == TOKSYM) {
		//printf("IT WAS A SYMBOL %s !\n", (**toks).arg);
		node->data = strdup((**toks).arg);
		++(*toks);
		return bw_parsesomething(node, toks);
	}
	if (bw_parseendbloc(node, toks) == 0)
		return bw_parsesomething(node->parent, toks);
	if (bw_parsebloc(node, toks) == 0)
		return bw_parsesomething(
				node->children[bwvec_size(node->children) - 1],
				toks
		);
	return 0;
}

static bw_html_t *bw_gethtmlfromtokens(bw_tokenarg_t const *toks) {
	bw_html_t *root = bw_nodenew(NULL);

	if (root == NULL)
		return NULL;
	printf("> %d\n", bw_parsesomething(root, &toks));
	return root;
}

#define REPEAT(s, n) for (int i = 0; i < n; ++i) printf("%s", s)
static void bw_display_tree(bw_html_t const *tree, int off) {
	REPEAT("  ", off);
	printf("%s:", tree->type ? tree->type : "root");
	if (tree->data)
		printf(" (%s)", tree->data);
	puts("");
	for (size_t n = 0; n < bwvec_size(tree->children); ++n)
		bw_display_tree(tree->children[n], off + 1);

}

// main

int main(void) {
	bw_tokenarg_t *tokens;
	char *content = "<html><h1>title</h1><p>hello</p></html>";

	//if (bw_getfilecontent(&content, "example.html") == -1)
	//	return 1;
	tokens = bw_gettokensfromhtml(content);
	if (tokens == NULL) {
		//free(content);
		return 1;
	}
	printf("%p\n", tokens);
	display_tokens(tokens);
	
	bw_html_t *node = bw_gethtmlfromtokens(tokens);
	printf("%zu\n", bwvec_size(node->children));
	bw_display_tree(node, 0);
	bw_nodeclose(node);

	for (size_t n = 0; n < bwvec_size(tokens); ++n)
		if (tokens[n].tok == TOKSYM && tokens[n].arg != NULL)
			free(tokens[n].arg);
	//free(content);
	bwvec_close(tokens);
	return 0;
}
