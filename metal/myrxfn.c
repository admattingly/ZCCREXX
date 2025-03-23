/* a simple REXX external function in Metal C */

/*
 * To compile:
 *
 * $ xlc -o myrxfn.s -S -qmetal -qnosearch -I /usr/include/metal -I /usr/include/zos myrxfn.c
 * $ as -o myrxfn.o -I CBC.SCCNSAM myrxfn.s
 * $ ld -o "//'MY.REXXLIB(MYRXFN)'" myrxfn.o
 *
 */

#pragma langlvl(extc99)             /* for stdbool.h */

#ifdef __64BIT__
#error This program must be compiled in 31-bit mode
#endif

#ifndef __IBM_METAL__
#error This program must be compiled with the Metal C compiler
#endif

/* need a custom prolog to restore GR0 (ENVBLOCK pointer) */
#pragma prolog(main, " MYPROLOG\n L 3,4(,13)\n L 0,20(,3)")
/* let epilog default to "main" epilog */

register void *envb __asm("r0");    /* ENVBLOCK pointer passed by REXX */

#define _MI_BUILTIN  1
#include <builtins.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <irxenvb.h>
#include <irxexte.h>
#include <irxevalb.h>
#include <irxargtb.h>
#include <irxshvb.h>

typedef int IRXFN(char *, ...);
#pragma linkage(IRXFN, OS)

#define REXXMAXVAR      250         /* maximum length of REXX variable name */

static bool drop(struct envblock *penvb, char *name, unsigned char *pret);
static bool getVar(struct envblock *penvb, char *name, void *value, unsigned int *pvaluelen, unsigned char *pret);
static bool say(struct envblock *penvb, char *text);
static bool setResult(struct envblock *penvb, struct evalblock **ppeval, char *result, size_t reslen);
static bool setVar(struct envblock *penvb, char *name, void *value, unsigned int valuelen, unsigned char *pret);

int main(int                    rs1,
         int                    rs2,
         int                    rs3,
         int                    rs4,
         struct argtable_entry  *arg,
         struct evalblock       **ppeval)
{
    struct envblock *penvb;
    int             n, textlen;
    char            *text, result[64];

    /* make a copy of the ENVB pointer in case we mess up GR0 */
    penvb = envb;

    /* set a NULL result for our function to keep REXX happy.
     * we will override this if we can send back a good result */
    (*ppeval)->evalblock_evlen = 0;

    /* examine function arguments */
    n = 0;
    /* length and pointer of 0xffffffff indicates end of argument list */
    while (!(arg[n].argtable_argstring_ptr == (void *)0xffffffff &&
             arg[n].argtable_argstring_length == 0xffffffff)) {
        switch (n) {
        case 0:     /* first parameter - integer for factorial calculation */
            textlen = arg[n].argtable_argstring_length;
            text    = arg[n].argtable_argstring_ptr;
            break;
        default:
            /* ignore extraneous arguments */
            break;
        }
        n++;
    }
    if (n != 1) {   /* wrong number of arguments */
        return -1;  /* non-zero return code triggers syntax error in REXX */
    }

    /* >>> processing goes here... */
    {
        /* for example, compute factorial of integer */
        long                x, z;
        unsigned long long  y, start, end;
        char                strx[32], msg[256], varvalue[32];
        unsigned int        varlen;
        double              elapsed;
        unsigned char       ret;
        bool                timing;

        /* convert function argument to an integer */
        if (textlen > sizeof(strx) - 1) {   /* argument is not a reasonable integer value */
            return -1;
        }
        memcpy(strx, text, textlen);
        strx[textlen] = '\0';
        x = strtol(strx, NULL, 10);
        if (x < 0 || x > 20) {  /* argument is outside valid range: 0 <= x <= 20 */
            return -1;
        }

        /* drop ELAPSED REXX variable */
        drop(penvb, "ELAPSED", &ret);

        /* get TIMEME variable.  If set to 1, keep track of elapsed time */
        timing = false;
        varlen = sizeof(varvalue) - 1;
        if (getVar(penvb, "TIMEME", varvalue, &varlen, &ret)) {
            varvalue[varlen] = '\0';
            if (strcmp(varvalue, "1") == 0) {
                timing = true;
            }
        }

        /* compute factorial */

        if (timing) {
            /* get system time */
            __asm(" STCKF %[time]" : [time] "=m"(start) : : );
        }

        y = 1;
        for (z = 1; z <= x; z++) {
            y *= z;
        }

        if (timing) {
            /* get system time */
            __asm(" STCKF %[time]" : [time] "=m"(end) : : );
        }

        if (timing) {
            elapsed = (end - start) / 4096.0;
            sprintf(varvalue, "%.6f", elapsed);
            varlen = strlen(varvalue);
            setVar(penvb, "ELAPSED", varvalue, varlen, &ret);
        }

        sprintf(result, "%llu", y);   /* convert result to a string */
    }
    /* <<< processing goes here... */

    /* load result into EVALBLOCK */
    if (!setResult(penvb, ppeval, result, strlen(result))) {
        return -1;
    }

    return 0;
}

bool drop(
        struct envblock *penvb,
        char            *name,
        unsigned char   *pret)
{
    char            msg[256];
    int             i, rc, zero = 0;
    char            rxname[REXXMAXVAR + 1];
    unsigned int    namelen;
    struct irxexte  *pexte;
    IRXFN           *excom;
    struct shvblock shvb;

    /* get pointer to IRXEXCOM routine */
    pexte = (struct irxexte *)penvb->envblock_irxexte;
    excom = (IRXFN *)pexte->irxexcom;

    /* load variable name and fold to upper case */
    namelen = strlen(name) < REXXMAXVAR ? strlen(name) : REXXMAXVAR;
    for (i = 0; i < namelen; i++) {
        rxname[i] = (char)toupper(name[i]);
    }
    /* drop the variable */
    memset(&shvb, 0x00, sizeof(shvb));
    shvb.shvcode = 'D';
    shvb.shvnama = rxname;
    shvb.shvnaml = namelen;

    (*excom)("IRXEXCOM", &zero, &zero, &shvb, &penvb, &rc);

    *pret = shvb.shvret;
    return (bool)(shvb.shvret < 0x08);
}

bool getVar(
        struct envblock *penvb,
        char            *name,
        void            *value,
        unsigned int    *pvaluelen,
        unsigned char   *pret)
{
    char            msg[256];
    int             i, rc, zero = 0;
    char            rxname[REXXMAXVAR + 1];
    unsigned int    namelen;
    struct irxexte  *pexte;
    IRXFN           *excom;
    struct shvblock shvb;

    /* get pointer to IRXEXCOM routine */
    pexte = (struct irxexte *)penvb->envblock_irxexte;
    excom = (IRXFN *)pexte->irxexcom;

    /* load variable name and fold to upper case */
    namelen = strlen(name) < REXXMAXVAR ? strlen(name) : REXXMAXVAR - 1;
    rxname[namelen] = '\0';
    for (i = 0; i < namelen; i++) {
        rxname[i] = (char)toupper(name[i]);
    }
    /* get a variable's value */
    memset(&shvb, 0x00, sizeof(shvb));
    shvb.shvcode = 'F';
    shvb.shvnama = rxname;
    shvb.shvnaml = namelen;
    shvb.shvvala = value;
    shvb.shvbufl = *pvaluelen;

    (*excom)("IRXEXCOM", &zero, &zero, &shvb, &penvb, &rc);

    *pvaluelen = shvb.shvvall;
    *pret = shvb.shvret;
    return (bool)(shvb.shvret < 0x08 && !(shvb.shvret & 0x01)); /* fail if variable doesn't exist */
}

bool say(struct envblock *penvb, char *text)
{
    struct irxexte  *pexte;
    IRXFN           *fnsay;
    int             rc, len;

    pexte = (struct irxexte *)penvb->envblock_irxexte;
    fnsay   = (IRXFN *)pexte->irxsay;

    /* try to SAY to the calling REXX environment */
    len = (int)strlen(text);
    (*fnsay)("WRITE   ", &text, &len, &penvb, &rc);

    return (bool)(rc == 0);
}

bool setResult(
        struct envblock     *penvb,
        struct evalblock    **ppeval,
        char                *result,
        size_t              reslen)
{
    struct irxexte  *pexte;
    IRXFN           *fnrlt;
    size_t          eblen;
    int             rc;
    char            msg[256];

    fnrlt = (IRXFN *)pexte->irxrlt;

    /* is supplied evalblock large enough for result? */
    eblen = (*ppeval)->evalblock_evsize * 8 - sizeof(struct evalblock);
    if (reslen > eblen) {
        /* allocate a new EVALBLOCK */
        (*fnrlt)("GETBLOCK", ppeval, reslen, &penvb, &rc);
        if (rc != 0) {
            sprintf(msg, "MYRXFN: Failed to expand EVALBLOCK. IRXRLT rc=%d", rc);
            say(penvb, msg);
            eblen = 0;      /* indicate that we cannot load the result */
        }
        else {
            eblen = (*ppeval)->evalblock_evsize * 8 - sizeof(struct evalblock);
        }
    }

    /* if any IRXRLT call failed to make the EVALBLOCK big enough, bail out */
    if (eblen < reslen) {
        return false;
    }

    /* load result into EVALBLOCK */
    memcpy((*ppeval)->evalblock_evdata, result, reslen);
    (*ppeval)->evalblock_evlen = reslen;

    return true;
}

bool setVar(
        struct envblock *penvb,
        char            *name,
        void            *value,
        unsigned int    valuelen,
        unsigned char   *pret)
{
    char            msg[256];
    int             i, rc, zero = 0;
    char            rxname[REXXMAXVAR + 1];
    unsigned int    namelen;
    struct irxexte  *pexte;
    IRXFN           *excom;
    struct shvblock shvb;

    /* get pointer to IRXEXCOM routine */
    pexte = (struct irxexte *)penvb->envblock_irxexte;
    excom = (IRXFN *)pexte->irxexcom;

    /* load variable name and fold to upper case */
    namelen = strlen(name) < REXXMAXVAR ? strlen(name) : REXXMAXVAR;
    for (i = 0; i < namelen; i++) {
        rxname[i] = (char)toupper(name[i]);
    }
    /* try to set a variable's value */
    memset(&shvb, 0x00, sizeof(shvb));
    shvb.shvcode = 'S';
    shvb.shvnama = rxname;
    shvb.shvnaml = namelen;
    shvb.shvvala = value;
    shvb.shvvall = valuelen;

    (*excom)("IRXEXCOM", &zero, &zero, &shvb, &penvb, &rc);

    *pret = shvb.shvret;
    return (bool)(shvb.shvret < 0x08);
}
