// Bowser Browser

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct {
	
} bw_htmlprop;

typedef struct s_bw_html {
	char *type;
	struct s_bw_html **children;
} bw_hmtl;

typedef enum {
	TOKOPEN,	// <
	TOKCLOSE,	// >
	TOKSLASH,	// /
	TOKSYM,
	TOKQUOTE,	// "
	TOKEND,
} bw_token;

typedef struct {
	bw_token type;
	char *arg;
} bw_tokenarg;

int bw_parsehtml(char const *html) {
	if (
}

int get_file_content(char **buf, char const *file) {
	int fd;
	struct stat st;

	if (buf == NULL || stat(file, &st) == -1)
		return -1;
	fd = open(file, O_RDONLY);
	if (fd == -1)
		return -1;
	*buf = malloc(st.st_size + 1);
	if (!*buf) {
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

int main(void) {
	char *content = NULL;

	if (get_file_content(&content, "./a.html") == -1)
		return 1;
	printf("%s\n", content);
	free(content);
	return 0;
}
