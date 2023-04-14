/* REXX */
/* Display help for CCA verb */

call ZCCREXX(ON)      /* install ZCCREXX host command environment */

trace off             /* suppress REXX tracing of failures */
ZCERRSAY = 0          /* suppress SAY of error messages    */
verb = ''
arg verb
if verb = '' then do
  say 'Usage: zchelp VERB'
  return 8
end

address ZCCREXX verb'?'

call ZCCREXX(OFF)     /* remove ZCCREXX host command environment */

