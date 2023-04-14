# ZCCREXX
### A REXX Productivity Tool for calling the IBM Common Cryptographic Architecture (CCA) API on z/OS
## Introduction
This tool drammatically simplifies the process of calling the IBM CCA API from REXX by providing a REXX "host command environment" that understands how to call CCA verbs and only requires you to populate the required verb arguments, providing default values for the rest.  It knows the data type and length of each argument, so integer arguments can be provided as REXX integers, rather than having to convert them to 4-byte binary form.  Similarly text arguments (e.g. key labels) can be provided as a string of any length, which ZCCREXX will automatically pad with spaces to the the required length (e.g. 64 characters for a key label).

To understand the value that ZCCREXX brings, let's look at an example of generating a random number using the CCA verb, CSNBRNGL.  To call CSNBRNGL directly from REXX, the code would look something like this:
```
return_code          = D2C(0, 4)
reason_code          = D2C(0, 4)
exit_data_length     = D2C(0, 4)
exit_data            = ""
rule_array_count     = D2C(1, 4)
rule_array           = "ODD     "
reserved_length      = D2C(0, 4)
reserved             = ""
random_number_length = D2C(24, 4)
random_number        = COPIES('00'x, 24)
address LINKPGM "CSNBRNGL" ,
  "return_code"            ,
  "reason_code"            ,
  "exit_data_length"       ,
  "exit_data"              ,
  "rule_array_count"       ,
  "rule_array"             ,
  "reserved_length"        ,
  "reserved"               ,
  "random_number_length"   ,
  "random_number"
say "CSNBRNGL rc="C2D(return_code)", reason="C2D(reason_code)
if C2D(return_code) = 0 then do
  say "Random number:" C2X(random_number)
end
```
Whereas, ZCCREXX requires much less code:
```
rule_array_count     = 1        /* Note: integer, not binary '00000001'x */
rule_array           = "ODD"    /* Note: no padding required */
random_number_length = 24
address ZCCREXX "CSNBRNGL"      /* Note: no need to supply arguments */
/* Note: a result "banner" is automatically SAYed, displaying return_code and reason_code */
if return_code = 0 then do
  say "Random number:" C2X(random_number)
end
```
## Installation
Upload the file, `zccrexx.xmit`, to your z/OS system.  Make sure the file transfer uses __BINARY__ mode (i.e. no character set translation).  Also make sure that the destination data set on z/OS has __LRECL=80__ and __RECFM=FB__ (or F). 

Then use the TSO __RECEIVE__ command to convert this data set to a PDSE.  For example:
```
receive inda('zccrexx.xmit')
 INMR901I Dataset ZCX100.SZCXLOAD from ADCDMST on S0W1   
 INMR154I The incoming data set is a 'PROGRAM LIBRARY'.  
 INMR906A Enter restore parameters or 'DELETE' or 'END' +
da('zccrexx.load')
```
Finally, make sure that this PDSE is in the STEPLIB concatenation (typically, or somewhere in the REXX external function search order. See: https://www.ibm.com/docs/en/zos/2.5.0?topic=subroutines-search-order) for the environment(s) where you are running your REXX programs.
## Programming with ZCCREXX
### The Basics
To use ZCCREXX in your REXX program, you must install the ZCCREXX _host command environment_, and as a matter of good _hygiene_, you should remove it when no longer needed.  Once installed, you can (optionally) make ZCCREXX the default command environment using the ADDRESS statement.  For example:
```
call ZCCREXX(ON)              /* Install the ZCCREXX host command environment */
address ZCCREXX               /* Make ZCCREXX the default command environment */

rule_array_count     = 1
rule_array           = "ODD"
random_number_length = 24
"CSNBRNGL"                    /* This command is passed to ZCCREXX */
if return_code = 0 then do
  say "Random number:" C2X(random_number)
end

call ZCCREXX(OFF)             /* Remove the ZCCREXX host command environment */
```
To call a CCA verb, consult the "CCA callable services" section of the "IBM z/OS Cryptographic Services ICSF Application Programmer's Guide" (see: https://www.ibm.com/docs/en/zos/2.5.0?topic=guide-cca-callable-services) for a description of the parameters passed to that verb.  ZCCREXX expects you to populate REXX variables with the required inputs before invoking the verb.  The REXX variables must be named exactly as the parameters are named in the IBM documentation.  Note, however, that REXX variable names are not case-sensitive. You do not need to define variables for optional input parameters or output-only parameters - ZCCREXX automatically sets null values for these parameters and populates REXX variables for the output parameters on return from calling the CCA verb.

If you place a question mark at the end of the CCA verb when invoking it using ZCCREXX, the verb is not executed.  Instead, ZCCREXX will SAY all the input and output parameters for that verb.

For example, this REXX program:
```
/* REXX */
trace o
ZCERRSAY = 0
call ZCCREXX(ON)              /* Install the ZCCREXX host command environment */
address ZCCREXX "CSNBRNGL?"
call ZCCREXX(OFF)             /* Remove the ZCCREXX host command environment */
```
produces the following output:
```
CSNBRNGL - Random Number Generate

     Type    Name
    -------  ----------------------------------------------------
  Mandatory input parameters:
    Integer  rule_array_count
    String   rule_array
    Integer  random_number_length

  Optional input parameters:
    Integer  exit_data_length
    String   exit_data
    Integer  reserved_length
    String   reserved

  Output parameters:
    Integer  return_code
    Integer  reason_code
    Integer  exit_data_length
    String   exit_data
    String   random_number
```
