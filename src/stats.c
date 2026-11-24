#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tracer.h"

typedef struct {
    long         nr;
    stat_entry_t s;
} row_t;

stats_t *stats_create(void)
{
    stats_t *st = calloc(1, sizeof *st);

    if (!st)
        perror("calloc");
    return st;
}

void stats_destroy(stats_t *st)
{
    free(st);
}

void stats_record(stats_t *st, const syscall_rec_t *r)
{
    stat_entry_t *e;

    if (r->nr < 0 || r->nr >= FILTER_MAX_NR)
        return;
    e = &st->e[r->nr];
    e->calls++;
    if (r->failed)
        e->errors++;
    if (r->dur_ns > 0)
        e->total_ns += r->dur_ns;
}

static int cmp_rows(const void *a, const void *b)
{
    const row_t *x = a, *y = b;

    if (x->s.total_ns != y->s.total_ns)
        return x->s.total_ns < y->s.total_ns ? 1 : -1;
    if (x->s.calls != y->s.calls)
        return x->s.calls < y->s.calls ? 1 : -1;
    return (x->nr > y->nr) - (x->nr < y->nr);
}

#define RULE "------ ----------- ----------- --------- --------- ----------------\n"

void stats_print(FILE *out, const stats_t *st)
{
    row_t        *rows = malloc(FILTER_MAX_NR * sizeof *rows);
    size_t        n = 0;
    int64_t       tot_ns = 0;
    unsigned long tot_calls = 0, tot_errs = 0;

    if (!rows) {
        perror("malloc");
        return;
    }
    for (long nr = 0; nr < FILTER_MAX_NR; nr++) {
        if (st->e[nr].calls == 0)
            continue;
        rows[n].nr = nr;
        rows[n].s  = st->e[nr];
        n++;
        tot_ns    += st->e[nr].total_ns;
        tot_calls += st->e[nr].calls;
        tot_errs  += st->e[nr].errors;
    }
    if (n == 0) {
        fputs("no system calls were traced\n", out);
        free(rows);
        return;
    }
    qsort(rows, n, sizeof *rows, cmp_rows);

    fputs("% time     seconds  usecs/call     calls    errors syscall\n", out);
    fputs(RULE, out);
    for (size_t i = 0; i < n; i++) {
        const stat_entry_t *s = &rows[i].s;
        const char *name = syscall_name(rows[i].nr);
        char        fb[32];
        double      pct = tot_ns > 0 ? 100.0 * (double)s->total_ns / (double)tot_ns : 0.0;
        long long   usec = (long long)(s->total_ns / 1000 / (int64_t)s->calls);

        if (!name) {
            snprintf(fb, sizeof fb, "syscall_%ld", rows[i].nr);
            name = fb;
        }
        fprintf(out, "%6.2f %11.6f %11lld %9lu ", pct, (double)s->total_ns / 1e9, usec, s->calls);
        if (s->errors)
            fprintf(out, "%9lu ", s->errors);
        else
            fprintf(out, "%9s ", "");
        fprintf(out, "%s\n", name);
    }
    fputs(RULE, out);
    fprintf(out, "%6.2f %11.6f %11s %9lu ", 100.0, (double)tot_ns / 1e9, "", tot_calls);
    if (tot_errs)
        fprintf(out, "%9lu ", tot_errs);
    else
        fprintf(out, "%9s ", "");
    fputs("total\n", out);
    free(rows);
}
