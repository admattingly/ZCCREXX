# ZCCREXX
### A REXX Productivity Tool for calling the IBM Common Cryptographic Architecture (CCA) API on z/OS
## Introduction
This tool drammatically simplifies the process of calling the IBM CCA API from REXX by providing a REXX "host command environment" that understands how to call CCA verbs and only requires you to populate the required verb parameters, providing default values for the rest.  It knows the data type and length of each parameter, so integer parameters can be provided as REXX integers, rather than having to convert them to 4-byte binary form.  Similarly text parameters (e.g. key labels) can be provided as a string of any length, which ZCCREXX will automatically pad with spaces to the the required length (e.g. 64 characters for a key label).

To understand the value that ZCCREXX brings, let's look at an example of generating a random number using the CCA verb, CSNBRNGL (see: https://www.ibm.com/docs/en/zos/2.5.0?topic=keys-random-number-generate-csnbrng-csnerng-csnbrngl-csnerngl).  

Without ZCCREXX, to call CSNBRNGL directly from REXX, the code would look something like this:
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
address ZCCREXX "CSNBRNGL"      /* Note: no need to supply verb parameters */
/* Note: a result "banner" is automatically SAYed, displaying return_code and reason_code */
if return_code = 0 then do
  say "Random number:" C2X(random_number)
end
```
## Installation
Upload the file, `zccrexx.xmit`, to your z/OS system.  Make sure the file transfer uses __BINARY__ mode (i.e. no ASCII/EBCDIC translation).  Also make sure that the destination data set on z/OS has __LRECL=80__ and __RECFM=FB__ (or F).

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
###Getting Help
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
A REXX program, `zcchelp.rexx`, is provided to facilitate displaying the parameters for a CCA verb.
### Samples
The _samples_ folder contains a number of REXX programs which demonstrate how to use ZCCREXX.  Feel free to use them as you see fit!
### ZCPACK Function
Several CCA verb parameters, particularly the _rule_array_ parameter, must be supplied as a concatenation of one or more fixed-length (typically 8-character) strings.  To make your code more legible, and to avoid errors specifying such parameters, ZCCREXX supplies a built-in function called __ZCPACK__.

This function takes two arguments:
1. (Mandatory) a space-delimited string comprising the words to be concatenated as fixed-length components of the output string.
2. (Optional) the length of each fixed-length component of the output string. The default length of each component is 8 characters.

Words in the input string must be separated by a single space.

Here are some examples of ZCPACK in action:
```
ZCPACK("")                   -> ""
ZCPACK("quick brown fox")    -> "quick   brown   fox     "
ZCPACK("quick brown fox", 4) -> "quicbrowfox "
ZCPACK("quick  brown   fox") -> "quick    brown          fox     "
/*                               |-------|-------|-------|------- */
```
Several of the sample REXX programs provided here demonstrate the use of the ZCPACK function.
## Pre-defined Variables
ZCCREXX recognises a set of (optional) pre-defined REXX variables, which can be used to customise the behavior of, or retrieve information about, ZCCREXX processing.
### ZCVERB
This variable is automatically set to the name of the last verb processed by ZCCREXX.
### ZCDESCRIPTION
This variable is automatically set to the title of the last verb processed by ZCCREXX.  If the verb is not recognised by ZCCREXX, this variable is set to "?".
### ZCERRM.
This stem variable contains the descriptive text (if any) corresponding to the return_code and reason_code for the last verb processed by ZCCREXX.  ZCERRM.0 contains an integer count of the number of lines of descriptive text.  The descriptive text is contained in variables, ZCERRM.1, ZCERRM.2, ..., ZCERRM.n, where _n_ is the count contained in ZCERRM.0.
### ZCTRACE
If you set this variable to 1, ZCCREXX uses MVS "write to operator" (WTO) calls to emit detailed trace information.  It is recommended that you do not use this capability, unless directed to do so by the author while attempting to chase down a bug in ZCCREXX.
### ZCERRSAY
Use this variable to customise the manner in which ZCCREXX SAYs the results of processing a CCA verb.  Depending on the value of ZCERRSAY, ZCCREXX will SAY 
1. a single-line "banner" showing the verb that was processed, and the resulting return_code and reason_code, AND/OR
2. a multi-line description corresponding to the return_code and reason_code

The value of ZCERRSAY is a bit mask, with each bit controlling the circumstances under which a banner and/or descriptive text is displayed, as follows:
```
     Bit
(as decimal) Meaning
------------ -----------------------------------------------------------------------------------------------------
      1      Banner produced for any return_code/reason_code
      2      Banner produced for return_code not zero OR reason_code not zero
      4      Banner produced for return_code negative or return_code >= 8
      8      Descriptive text produced for any return_code/reason_code
     16      Descriptive text produced for return_code not zero OR reason_code not zero
     32      Descriptive text produced for return_code negative or return_code >= 8
     64      Help requested (RC=-100) is treated as a warning, otherwise treated as return_code = reason_code = 0
```
The __default value of ZCERRSAY is 1 + 16 + 64 = 81__.  To suppress all SAYs of error information by ZCCREXX, set ZCERRSAY = 0.

Note that the setting of ZCCERRSAY has no effect on the stem variable, ZCCERRM.  It is always populated with descriptive text corresponding to the value of return_code and reason_code.
### ZCERRLINELEN
Use this variable to set the maximum line length for descriptive text.  The minimum line length is 55 characters, the default is 75 characters and the maximum line length is 255 characters.  The value of this variable has no effect on the "banner" line, if ZCERRSAY is set so that a banner is produced.
### ZCERRLINESPACE
Use this variable to control how many lines of space are SAYed after each (unformatted) line of descriptive text.  The default is 0 = no line spacing and the maximum is 2 lines.

Note that the setting of ZCCERRLINESPACE has no effect on the stem variable, ZCCERRM.
### ZCERRINDENT
Use this variable to set the number of spaces SAYed at the start of each line of descriptive text (if any).  

Note that the setting of ZCCERRINDENT has no effect on the stem variable, ZCCERRM.
## Restrictions
ZCCREXX implements the full gamut of (156) z/OS ICSF CCA verbs except for:
1. Privileged verbs: CSFACEE, CSFWRP and CSFPCI.
2. CSNBxxx1 and CSNBxxx3 variants of data protection and integrity verbs (e.g. CSNBENC1, CSNBCCT3, etc) that accept an ALET for some parameters.  For those base functions that accept an ALET parameter (i.e. CSNBFLD and CSNBFLE), a non-zero ALET value is ignored, forcing all parameter values to be sourced from the primary address space.
3. 64-bit variants (i.e. CSFxxx6, CSNExxx and CSNFxxx) are not supported.
