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
Upload the file, `zccrexx.seq`, to your z/OS system.  Make sure the file transfer uses BINARY mode (i.e. no character set translation).  Also make sure that the destination data set on z/OS has LRECL=80 and RECFM=FB (or F). 
