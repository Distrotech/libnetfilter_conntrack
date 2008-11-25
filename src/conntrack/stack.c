/*
 * (C) 2008 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "internal/stack.h"

struct stack {
	int num_elems;
	int max_elems;
	size_t elem_size;
	char *data;
};

struct stack *stack_create(size_t elem_size, int max_elems)
{
	struct stack *s;

	s = calloc(sizeof(struct stack), 1);
	if (s == NULL)
		return NULL;

	s->data = calloc(elem_size * max_elems, 1);
	if (s->data == NULL) {
		free(s);
		return NULL;
	}
	s->elem_size = elem_size;
	s->max_elems = max_elems;

	return s;
}

void stack_destroy(struct stack *s)
{
	free(s->data);
	free(s);
}

int stack_push(struct stack *s, void *data)
{
	if (s->num_elems >= s->max_elems) {
		errno = ENOSPC;
		return -1;
	}
	memcpy(s->data + (s->elem_size * s->num_elems), data, s->elem_size);
	s->num_elems++;
	return 0;
}

int stack_pop(struct stack *s, void *data)
{
	if (s->num_elems <= 0) {
		errno = EINVAL;
		return -1;
	}
	s->num_elems--;
	memcpy(data, s->data + (s->elem_size * s->num_elems), s->elem_size);
	return 0;
}
