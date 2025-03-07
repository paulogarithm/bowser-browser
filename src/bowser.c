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

int bwvec_extendoff(void *vptr, void *membs, size_t moremembs, size_t off) {
	bwvecmeta_t *v = *(bwvecmeta_t **)vptr - 1;

	if (v->maxmemb < v->nmemb + moremembs) {
		v->maxmemb += moremembs;
		v = realloc(v, sizeof(bwvecmeta_t) + v->elemsize * v->maxmemb);
		if (v == NULL)
		return -1;
	}
	(void)memcpy(((char *)(v + 1)) + (v->nmemb * v->elemsize) - off, membs, v->elemsize * moremembs);
	v->nmemb += moremembs;
	*(void **)vptr = v + 1;
	return 0;
}

int bwvec_extend(void *vptr, void *membs, size_t moremembs) {
	return bwvec_extendoff(vptr, membs, moremembs, 0);
}

// hashmap

typedef struct {
	char const *key;
	size_t value;
} bwhmap_keyval_t;

typedef struct s_bwhmap {
	//size_t keysize;
	//size_t valuesize;
	size_t size;
	bwhmap_keyval_t **data;
	size_t(*hashfunc)(char const *, size_t, size_t);
} bwhmap_t;

//#define BWHMAP_NEW(kt, vt, n) bwhmap_init(sizeof(kt), sizeof(vt), n, bwhmap_hashadler32)
#define BWHMAP_NEW(n) bwhmap_init(n, bwhmap_hashadler32)
//#define BWHMAP_HASHKEY(hmap, key) ((hmap)->hashfunc(key, (hmap)->keysize, (hmap)->size)) 

bwhmap_t *bwhmap_init(size_t size, size_t(*f)(char const *, size_t, size_t)) {
	bwhmap_t *map = malloc(sizeof(bwhmap_t));

	if (map == NULL)
		return NULL;
	map->data = malloc(sizeof(void *) * size);
	for (size_t n = 0; n < size; ++n)
		map->data[n] = BWVEC_NEW(bwhmap_keyval_t);
	//map->keysize = keysize;
	//map->valuesize = valuesize;
	map->size = size;
	map->hashfunc = f;
	return map;
}

size_t bwhmap_hashadler32(char const *key, size_t keysize, size_t hmapsize) {
	uint8_t const *buffer = (uint8_t const *)key;
    uint32_t s1 = 1;
    uint32_t s2 = 0;

	for (size_t n = 0; n < keysize; n++) {
		s1 = (s1 + buffer[n]) % 65521;
		s2 = (s2 + s1) % 65521;
	}
	return (size_t)((s2 << 16) | s1) % hmapsize;
}

void bwhmap_set(bwhmap_t *hmap, char const *key, size_t value) {
	bwhmap_keyval_t const keyval = { .key = key, .value = value };
	bwhmap_keyval_t *list = hmap->data[hmap->hashfunc(key, strlen(key), hmap->size)];
	size_t const size = bwvec_size(list);

	for (size_t n = 0; n < size; ++n)
		if (strcmp(list[n].key, key) == 0) {
			list[n].value = value;
			return;
		}
	(void)bwvec_pushdata(&list, &keyval);
}

size_t *bwhmap_get(bwhmap_t *hmap, void const *key) {
	bwhmap_keyval_t *list = hmap->data[hmap->hashfunc(key, strlen(key), hmap->size)];
	size_t size = bwvec_size(list);

	for (size_t n = 0; n < size; ++n)
		if (strcmp(list[n].key, key) == 0)
			return &list[n].value;
	return NULL;
}

void bwhmap_close(bwhmap_t *hmap) {
	for (size_t n = 0; n < hmap->size; ++n)
		bwvec_close(hmap->data[n]);
	free(hmap->data);
	free(hmap);
}

// tokenizer

typedef enum {
	TOKOPEN,	// <
	TOKCLOSE,	// >
	TOKSLASH,	// /
	TOKSYM,		// anything else
	TOKQUOTE,	// "
	TOKEQUAL, 	// =
	TOKEXCLAM,	// !
	TOKEND,
} bw_token_t;

static bw_token_t const CHAR2TOK_MAP[] = { // a waste of memory
	['='] = TOKEQUAL,
	['/'] = TOKSLASH,
	['"'] = TOKQUOTE,
	['!'] = TOKEXCLAM,
};

static char const *const TOK2STR_MAP[] = {
	[TOKOPEN] = "<",
	[TOKCLOSE] = ">",
	[TOKSLASH] = "/",
	[TOKSYM] = "TOKSYM",
	[TOKQUOTE] = "\"",
	[TOKEQUAL] = "=",
	[TOKEXCLAM] = "!",
	[TOKEND] = "END"
};

typedef struct {
	bw_token_t tok;
	char *arg;
} bw_tokenarg_t;

// tokenizer

static bw_tokenarg_t *bw_gettokensfromstring(char const *html) {
	bw_tokenarg_t *toks = BWVEC_NEW(bw_tokenarg_t);
	char *buf = BWVEC_NEW(char);
	bw_tokenarg_t tmp = { .tok = TOKEND, .arg = NULL };
	bw_token_t actual;
	bool in = false;
	bool instr = false;

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
				if (!in)
					(void)bwvec_pushnum(&buf, *html);
				else {
					actual = TOKCLOSE;
					in = false;
				}
				break;
			case '=':
			case '"':
			case '/':
			case '!':
				if ((in && !instr) || (in && *html == '"'))
					actual = CHAR2TOK_MAP[(int)*html];
				else
					(void)bwvec_pushnum(&buf, *html);
				if (*html == '"')
					instr = !instr;
				break;
			case ' ':
			case '\n':
			case '\t':
				if (in && !instr)
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

static void display_tokens(bw_tokenarg_t const *args) {
	size_t size = bwvec_size(args);

	for (size_t n = 0; n < size; ++n) {
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

typedef struct {
	bwhmap_t *singlemap;
} bw_htmlcommondata_t;

typedef struct s_bw_html {
	char *type;
	char *data;
	bw_htmlprop_t *props;
	struct s_bw_html *parent;
	struct s_bw_html **children;
	struct s_bw_html *root;
	bw_htmlcommondata_t *common;
} bw_html_t;

static bw_html_t *bw_nodenew(char const *type) {
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
	node->root = node;
	node->common = NULL;
	return node;
}

static int bw_commoninit(bw_html_t *node) {
	node->common = malloc(sizeof(bw_htmlcommondata_t));
	if (node->common == NULL)
		return -1;
	node->common->singlemap = BWHMAP_NEW(8);
	if (node->common->singlemap == NULL)
		return -1;
	bwhmap_set(node->common->singlemap, "br", 1);
	bwhmap_set(node->common->singlemap, "meta", 1);
	bwhmap_set(node->common->singlemap, "img", 1);
	bwhmap_set(node->common->singlemap, "input", 1);
	return 0;
}

static void bw_commondestroy(bw_htmlcommondata_t *data) {
	bwhmap_close(data->singlemap);
	free(data);
}

static void bw_nodeadopt(bw_html_t *node, bw_html_t *child) {
	if (child == NULL)
		return;
	child->parent = node;
	child->root = node->root;
	child->common = node->root->common;
	(void)bwvec_pushptr(&node->children, child);
}

void bw_htmlclose(bw_html_t *node);

// stringelem ::= TOKQUOTE TOKSYM TOKQUOTE
static int bw_parsestringelem(bw_htmlprop_t *prop, bw_tokenarg_t const **toks) {
	if ((*toks)[0].tok == TOKQUOTE && (*toks)[1].tok == TOKQUOTE) {
		prop->value = NULL;
		*toks += 2;
		return 0;
	}
	if ((*toks)[0].tok != TOKQUOTE ||
			(*toks)[1].tok != TOKSYM ||
			(*toks)[2].tok != TOKQUOTE)
		return -1;
	prop->value = strdup((*toks)[1].arg);
	*toks += 3;
	return 0;
}

// keyval ::= TOKSYM TOKEQUAL (<stringelem> | TOKSYM)
static int bw_parsekeyval(bw_html_t *node, bw_tokenarg_t const **toks) {
	bw_htmlprop_t prop;
	char *tmp;

	if ((*toks)[0].tok != TOKSYM || (*toks)[1].tok != TOKEQUAL)
		return -1;
	tmp = (**toks).arg;
	*toks += 2;
	if (bw_parsestringelem(&prop, toks) == -1) {
		if ((*toks)[0].tok == TOKSYM) {
			prop.value = strdup((*toks)[0].arg);
			++*toks;
		} else
			return -1; // error: not string/sym
	}
	prop.key = strdup(tmp);
	(void)bwvec_pushdata(&node->props, &prop);
	return 0;
}

// bloc ::= TOKOPEN TOKSYM [<keyval>] TOKCLOSE
static int bw_parsebloc(bw_html_t *node, bw_tokenarg_t const **toks, int *in) {
	bw_html_t *child;
	_Bool x;

	if ((*toks)[0].tok != TOKOPEN || (*toks)[1].tok != TOKSYM)
		return -1;
	child = bw_nodenew((*toks)[1].arg);
	*toks += 2;
	while (bw_parsekeyval(child, toks) == 0);
	x = (**toks).tok == TOKSLASH;
	if (x || bwhmap_get(node->common->singlemap, child->type) != NULL) {
		*in = 0;
		*toks += x;
	}
	if ((**toks).tok != TOKCLOSE) {
		bw_htmlclose(child);
		return -1; // error: bloc not closed by '>'
	}
	bw_nodeadopt(node, child);
	++*toks;
	return 0;
}

// endbloc ::= TOKOPEN TOKSLASH TOKSYM TOKCLOSE
static int bw_parseendbloc(bw_html_t *node, bw_tokenarg_t const **toks) {
	if ((*toks)[0].tok != TOKOPEN ||
			(*toks)[1].tok != TOKSLASH ||
			(*toks)[2].tok != TOKSYM ||
			(*toks)[3].tok != TOKCLOSE)
		return -1;
	if (strcmp(node->type, (*toks)[2].arg))
		return -1; // error: expected same node
	(*toks) += 4;
	return 0;
}

// useless ::= TOKOPEN TOKEXCLAM ... TOKCLOSE
static int bw_parseuseless(bw_tokenarg_t const **args) {
	if ((*args)[0].tok != TOKOPEN || (*args)[1].tok != TOKEXCLAM)
		return -1;
	*args += 2;
	for (; (**args).tok != TOKCLOSE; ++*args);
	++*args;
	return 0;
}

// something ::= TOKSYM | <endbloc> | <bloc>
static int bw_parsesomething(bw_html_t *node, bw_tokenarg_t const **toks) {
	int go_in = 1;

	if ((**toks).tok == TOKEND)
		return 0;
	if ((**toks).tok == TOKSYM) {
		if (node->data != NULL)
			(void)bwvec_extendoff(&node->data, (**toks).arg, strlen((**toks).arg) + 1, 1);
		else {
			node->data = BWVEC_NEW(char);
			(void)bwvec_extend(&node->data, (**toks).arg, strlen((**toks).arg) + 1);
		}
		++(*toks);
		return bw_parsesomething(node, toks);
	}
	if (bw_parseuseless(toks) == 0)
		return bw_parsesomething(node, toks);
	if (bw_parseendbloc(node, toks) == 0)
		return bw_parsesomething(node->parent, toks);
	if (bw_parsebloc(node, toks, &go_in) == 0)
		return bw_parsesomething(go_in ?
			node->children[bwvec_size(node->children) - 1] : node, toks);
	printf("[failed to in %s, last token is %s, with arg %s.]\n", node->type ? node->type : "root", TOK2STR_MAP[(**toks).tok], (**toks).arg ? (**toks).arg : "null");
	return -1;
}

static bw_html_t *bw_gethtmlfromtokens(bw_tokenarg_t const *toks) {
	bw_html_t *root = bw_nodenew(NULL);
	int res;

	if (root == NULL)
		return NULL;
	//display_tokens(toks);
	if (bw_commoninit(root) == -1)
		return NULL;
	res = bw_parsesomething(root, &toks);
	printf("Result is %d\n", res);
	//if (res == -1) {
	//	bw_htmlclose(root);
	//	return NULL;
	//}
	return root;
}

#define REPEAT(s, n) for (int i = 0; i < n; ++i) printf("%s", s)
static void bw_display_tree(bw_html_t const *tree, int off) {
	size_t size = bwvec_size(tree->children);

	REPEAT("   ", off);
	printf("%s:", tree->type ? tree->type : "root");
	if (tree->data)
		printf(" (...)");//, tree->data);
	if (!bwvec_empty(tree->props))
		printf(" [%zu props]", bwvec_size(tree->props));
	puts("");
	for (size_t n = 0; n < size; ++n)
		bw_display_tree(tree->children[n], off + 1);
}

// html api

bw_html_t *bw_htmlfromtext(char const *htmltext) {
	bw_tokenarg_t *tokens = bw_gettokensfromstring(htmltext);
	bw_html_t *html;
	size_t size;

	if (tokens == NULL)
		return NULL;
	html = bw_gethtmlfromtokens(tokens);
	size = bwvec_size(tokens);
	for (size_t n = 0; n < size; ++n)
		if (tokens[n].tok == TOKSYM && tokens[n].arg != NULL)
			free(tokens[n].arg);
	bwvec_close(tokens);
	return html;
}

bw_html_t *bw_htmlfromfile(char const *path) {
	char *content;
	bw_html_t *node;

	if (bw_getfilecontent(&content, path) == -1)
		return NULL;
	node = bw_htmlfromtext(content);
	free(content);
	return node;
}

void bw_htmlclose(bw_html_t *node) {
	size_t size = bwvec_size(node->props);
	static bool commonhasbeenclosed = false;

	for (size_t n = 0; n < size; ++n) {
		free(node->props[n].key);
		if (node->props[n].value != NULL)
			free(node->props[n].value);
	}
	bwvec_close(node->props);
	if (node->type != NULL)
		free(node->type);
	if (!commonhasbeenclosed && node->common != NULL) {
		bw_commondestroy(node->common);
		commonhasbeenclosed = true;
	}
	size = bwvec_size(node->children);
	for (size_t n = 0; n < size; ++n)
		bw_htmlclose(node->children[n]);
	bwvec_close(node->children);
	if (node->data != NULL)
		bwvec_close(node->data);
	free(node);
}

// main

int main(void) {
	bw_html_t *html = bw_htmlfromfile("example.html");

	if (html == NULL)
		return 1;
	bw_display_tree(html, 0);
	bw_htmlclose(html);
	return 0;
}
