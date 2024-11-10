/* REXX */
/* Create ECC and Dilithium keys for SMF record signing */

arg token .
if token = '' then do
  say 'Usage: smfkeys token_root_name'
  return 8
end

/* pad tokens out to 32 characters to keep SMF happy */
ecctoken = left(token'.ECC', 32, '#')
li2token = left(token'.LI2', 32, '#')

call ZCCREXX(ON)      /* install ZCCREXX host command environment */
address ZCCREXX       /* send commands to ZCCREXX by default      */

zcerrsay = 2   /* only show banner for errors */

/* define PKCS #11 constants */
call zcpdefs

/* create ECDSA token */
handle                = ecctoken
rule_array            = zcpack('TOKEN')
rule_array_count      = length(rule_array) / 8
attribute_list        = left('IBM', 32) || left('CEX8S', 16) || '3141592653589793' || '00000000'x
attribute_list_length = length(attribute_list)

zcerrsay = 0    /* suppress error banner, because token may exist */
'CSFPTRC'
zcerrsay = 2

if return_code = 8 & reason_code = 3021 then do
  rule_array            = zcpack('TOKEN RECREATE')
  rule_array_count      = length(rule_array) / 8

  'CSFPTRC'
end

if return_code \= 0 then signal getout

/* create Dilithium token */
handle                = li2token
rule_array            = zcpack('TOKEN')
rule_array_count      = length(rule_array) / 8
attribute_list        = left('IBM', 32) || left('CEX8S', 16) || '3141592653589793' || '00000000'x
attribute_list_length = length(attribute_list)

zcerrsay = 0
'CSFPTRC'
zcerrsay = 2

if return_code = 8 & reason_code = 3021 then do
  rule_array            = zcpack('TOKEN RECREATE')
  rule_array_count      = length(rule_array) / 8

  'CSFPTRC'
end

if return_code \= 0 then signal getout

zctrace = 1

/* generate ECDSA key pair */
token_handle                      = ecctoken
rule_array_count                  = 0
public_key_attribute_list         = zcalist(CKA_CLASS,      CKO_PUBLIC_KEY,       ,
                                            CKA_KEY_TYPE,   CKK_EC,               ,
                                            CKA_TOKEN,      CK_TRUE,              ,
                                            CKA_VERIFY,     CK_TRUE,              ,
                                            CKA_EC_PARAMS,  zcoid('1.3.132.0.35'))  /* secp521r1 */
public_key_attribute_list_length  = length(public_key_attribute_list)
private_key_attribute_list        = zcalist(CKA_CLASS,      CKO_PRIVATE_KEY,      ,
                                            CKA_KEY_TYPE,   CKK_EC,               ,
                                            CKA_TOKEN,      CK_TRUE,              ,
                                            CKA_SIGN,       CK_TRUE,              ,
                                            CKA_IBM_SECURE, CK_FALSE)  /* set to CK_TRUE with EP11 */
private_key_attribute_list_length = length(private_key_attribute_list)

'CSFPGKP'

if return_code \= 0 then signal getout

/* save object handles */
eccpubobject = public_key_object_handle
eccpriobject = private_key_object_handle

/* generate CRYSTALS-Dilithium key pair */
token_handle                      = li2token
rule_array_count                  = 0
public_key_attribute_list         = zcalist(CKA_CLASS,              CKO_PUBLIC_KEY,    ,
                                            CKA_KEY_TYPE,           CKK_IBM_DILITHIUM, ,
                                            CKA_TOKEN,              CK_TRUE,           ,
                                            CKA_VERIFY,             CK_TRUE,           ,
                                            CKA_IBM_DILITHIUM_MODE, zcoid('1.3.6.1.4.1.2.267.1.6.5'))  /* 6,5 Round 2 */
public_key_attribute_list_length  = length(public_key_attribute_list)
private_key_attribute_list        = zcalist(CKA_CLASS,              CKO_PRIVATE_KEY,   ,
                                            CKA_KEY_TYPE,           CKK_IBM_DILITHIUM, ,
                                            CKA_TOKEN,              CK_TRUE,           ,
                                            CKA_SIGN,               CK_TRUE,           ,
                                            CKA_IBM_SECURE,         CK_FALSE)  /* set to CK_TRUE with EP11 */
private_key_attribute_list_length = length(private_key_attribute_list)

'CSFPGKP'

if return_code \= 0 then signal getout

/* save object handles */
li2pubobject = public_key_object_handle
li2priobject = private_key_object_handle

/* show off what we built */
say ' '
say 'ECDSA Public Key Object:' eccpubobject
call list_object(eccpubobject)
say ' '
say 'ECDSA Private Key Object:' eccpriobject
call list_object(eccpriobject)
say ' '
say 'Dilithium Public Key Object:' li2pubobject
call list_object(li2pubobject)
say ' '
say 'Dilithium Private Key Object:' li2priobject
call list_object(li2priobject)

getout:

call ZCCREXX(OFF)     /* remove ZCCREXX host command environment  */

return

list_object:
arg handle

handle = left(handle, 44)
rule_array_count = 0
attribute_list_length = 10000
attribute_list = copies('00'x, 10000)

'CSFPGAV'

if return_code = 0 then do
  at = left(attribute_list, attribute_list_length)
  n = c2d(left(at, 2))
  p = 3
  say '  Attributes:' n
  do i = 1 to n
    name = substr(at, p, 4)
    p = p + 4
    len = c2d(substr(at, p, 2))
    p = p + 2
    val = c2x(substr(at, p, len))
    valstr = ''
    if name = CKA_CLASS then do
      xp = 'X' || val
      valstr = CKO.xp
    end
    if name = CKA_KEY_TYPE then do
      xp = 'X' || val
      valstr = CKK.xp
    end
    p = p + len
    xp = 'X' || c2x(name)
    say '    'c2x(name) left(cka.xp, 30) '= ('len')' val valstr
  end
end

return
