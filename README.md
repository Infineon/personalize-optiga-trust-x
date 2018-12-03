# Personalize your OPTIGA™ Trust X sample with Embedded Linux

## Description

This repository contains one of Application Notes for [OPTIGA™ Trust X](www.infineon.com/optiga-trust-x) security chip.

* You can find more information about the security chip in the core [repository](https://github.com/Infineon/optiga-trust-x)
* You can find other Application Notes in the respective [repository](https://github.com/Infineon/appnotes-optiga-trust-x)

## Summary
In this guide you may find the following steps:
* How to issue your own self-signed CA certificate with openSSL
* How to generate a Certificate Signing Request (CSR) with OPTIGA™ Trust X and sign it with the CA
* How to generate an end-device certificate and write it back to one of available certificate slots on the device

## Hardware and Software
For this application note you need to have:
* Embedded Linux Platform with open GPIO and i2c interface
* OPTIGA™ Trust X which is possile to connect to i2c lines on the Linux board

## Build from sources

In order to obtain the sources we recommend to use following command:
```console
git clone --recursive https://github.com/Infineon/personalize-optiga-trust-x
```

Prior using the perso application note you need to build required executables from provided sources.
Copy this repository to your embedded system using any available method (USB stick, SSH transfer, SCP, etc.)
```console
pi@raspberrypi:~ $ cd personalize-optiga-trust-x/source
pi@raspberrypi:~/personalize-optiga-trust-x/source $ make
```
During the build process you should see console output as shown below
<details> 
  <summary> Built process of mbedTLS and OPTIGA Trust X library</summary>

```console
mkdir -p ./build
mkdir -p ./../executables
make -C ./mbedtls-2.6.0/ no_test
make[1]: Entering directory '/home/pi/personalize-optiga-trust-x/source/mbedtls-2.6.0'
make[2]: Entering directory '/home/pi/personalize-optiga-trust-x/source/mbedtls-2.6.0/library'
  CC    aes.c
  CC    aesni.c
  CC    arc4.c
  CC    asn1parse.c
  CC    asn1write.c
  CC    base64.c
  CC    bignum.c
  CC    blowfish.c
  CC    camellia.c
  CC    ccm.c
  CC    cipher.c
  CC    cipher_wrap.c
  CC    cmac.c
  CC    ctr_drbg.c
  CC    des.c
  CC    dhm.c
  CC    ecdh.c
  CC    ecdsa.c
  CC    ecjpake.c
  CC    ecp.c
  CC    ecp_curves.c
  CC    entropy.c
  CC    entropy_poll.c
  CC    error.c
  CC    gcm.c
  CC    havege.c
  CC    hmac_drbg.c
  CC    md.c
  CC    md2.c
  CC    md4.c
  CC    md5.c
  CC    md_wrap.c
  CC    memory_buffer_alloc.c
  CC    oid.c
  CC    padlock.c
  CC    pem.c
  CC    pk.c
  CC    pk_wrap.c
  CC    pkcs12.c
  CC    pkcs5.c
  CC    pkparse.c
  CC    pkwrite.c
  CC    platform.c
  CC    ripemd160.c
  CC    rsa.c
  CC    sha1.c
  CC    sha256.c
  CC    sha512.c
  CC    threading.c
  CC    timing.c
  CC    version.c
  CC    version_features.c
  CC    xtea.c
  AR    libmbedcrypto.a
  RL    libmbedcrypto.a
  CC    certs.c
  CC    pkcs11.c
  CC    x509.c
  CC    x509_create.c
  CC    x509_crl.c
  CC    x509_crt.c
  CC    x509_csr.c
  CC    x509write_crt.c
  CC    x509write_csr.c
  AR    libmbedx509.a
  RL    libmbedx509.a
  CC    debug.c
  CC    net_sockets.c
  CC    ssl_cache.c
  CC    ssl_ciphersuites.c
  CC    ssl_cli.c
  CC    ssl_cookie.c
  CC    ssl_srv.c
  CC    ssl_ticket.c
  CC    ssl_tls.c
  AR    libmbedtls.a
  RL    libmbedtls.a
make[2]: Leaving directory '/home/pi/personalize-optiga-trust-x/source/mbedtls-2.6.0/library'
make[2]: Entering directory '/home/pi/personalize-optiga-trust-x/source/mbedtls-2.6.0/programs'
  CC    aes/aescrypt2.c
  CC    aes/crypt_and_hash.c
  CC    hash/hello.c
  CC    hash/generic_sum.c
  CC    pkey/dh_client.c
  CC    pkey/dh_genprime.c
  CC    pkey/dh_server.c
  CC    pkey/ecdh_curve25519.c
  CC    pkey/ecdsa.c
  CC    pkey/gen_key.c
  CC    pkey/key_app.c
  CC    pkey/key_app_writer.c
  CC    pkey/mpi_demo.c
  CC    pkey/pk_decrypt.c
  CC    pkey/pk_encrypt.c
  CC    pkey/pk_sign.c
  CC    pkey/pk_verify.c
  CC    pkey/rsa_genkey.c
  CC    pkey/rsa_decrypt.c
  CC    pkey/rsa_encrypt.c
  CC    pkey/rsa_sign.c
  CC    pkey/rsa_verify.c
  CC    pkey/rsa_sign_pss.c
  CC    pkey/rsa_verify_pss.c
  CC    ssl/dtls_client.c
  CC    ssl/dtls_server.c
  CC    ssl/ssl_client1.c
  CC    ssl/ssl_client2.c
  CC    ssl/ssl_server.c
  CC    ssl/ssl_server2.c
  CC    ssl/ssl_fork_server.c
  CC    ssl/mini_client.c
  CC    ssl/ssl_mail_client.c
  CC    random/gen_entropy.c
  CC    random/gen_random_havege.c
  CC    random/gen_random_ctr_drbg.c
  CC    test/ssl_cert_test.c
  CC    test/benchmark.c
  CC    test/selftest.c
  CC    test/udp_proxy.c
  CC    util/pem2der.c
  CC    util/strerror.c
  CC    x509/cert_app.c
  CC    x509/crl_app.c
  CC    x509/cert_req.c
  CC    x509/cert_write.c
  CC    x509/req_app.c
make[2]: Leaving directory '/home/pi/personalize-optiga-trust-x/source/mbedtls-2.6.0/programs'
make[1]: Leaving directory '/home/pi/personalize-optiga-trust-x/source/mbedtls-2.6.0'
Compiling optiga_trust_x/optiga/crypt/optiga_crypt.c
Compiling optiga_trust_x/optiga/util/optiga_util.c
Compiling optiga_trust_x/optiga/cmd/CommandLib.c
Compiling optiga_trust_x/optiga/common/Logger.c
Compiling optiga_trust_x/optiga/common/Util.c
Compiling optiga_trust_x/optiga/comms/optiga_comms.c
Compiling optiga_trust_x/optiga/comms/ifx_i2c/ifx_i2c.c
Compiling optiga_trust_x/optiga/comms/ifx_i2c/ifx_i2c_config.c
Compiling optiga_trust_x/optiga/comms/ifx_i2c/ifx_i2c_data_link_layer.c
Compiling optiga_trust_x/optiga/comms/ifx_i2c/ifx_i2c_physical_layer.c
Compiling optiga_trust_x/optiga/comms/ifx_i2c/ifx_i2c_transport_layer.c
Compiling optiga_trust_x/pal/linux/pal.c
Compiling optiga_trust_x/pal/linux/pal_gpio.c
Compiling optiga_trust_x/pal/linux/pal_i2c.c
Compiling optiga_trust_x/pal/linux/pal_ifx_i2c_config.c
Compiling optiga_trust_x/pal/linux/pal_os_event.c
Compiling optiga_trust_x/pal/linux/pal_os_lock.c
Compiling optiga_trust_x/pal/linux/pal_os_timer.c
Compiling json_parser/cJSON.c
Compiling json_parser/JSON_parser.c
Compiling optiga_generate_csr.c
optiga_generate_csr.c: In function ‘__optiga_sign_wrap’:
optiga_generate_csr.c:88:35: warning: passing argument 1 of ‘optiga_crypt_ecdsa_sign’ discards ‘const’ qualifier from pointer target type [-Wdiscarded-qualifiers]
  status = optiga_crypt_ecdsa_sign(hash, hash_len, optiga_key_id, der_signature, &ds_len);
                                   ^~~~
In file included from optiga_generate_csr.c:54:0:
./optiga_trust_x/optiga/include/optiga/optiga_crypt.h:403:21: note: expected ‘uint8_t * {aka unsigned char *}’ but argument is of type ‘const unsigned char *’
 optiga_lib_status_t optiga_crypt_ecdsa_sign(uint8_t * digest,
                     ^~~~~~~~~~~~~~~~~~~~~~~
optiga_generate_csr.c:102:30: warning: format ‘%lu’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘size_t {aka unsigned int}’ [-Wformat=]
     mbedtls_printf( " Size %lu\n", *sig_len);
                              ^
Linking ../executables/optiga_generate_csr
Compiling optiga_upload_crt.c
Linking ../executables/optiga_upload_crt
```
</details>

Your binaries are ready to be used and can be found in the folder executables in the root directory of your project

## Usage examples for binaries

```console
pi@raspberrypi:~/personalize-optiga-trust-x/executables $ ./optiga_generate_csr -f /dev/i2c-1 -o optiga.csr -i ../IO_files/config.jsn
```
* `-f /dev/i2c-1` Path to the i2c device to which # Infineon's OPTIGA&trade; Trust X is connected
* `-o optiga.csr` Path to a file, where a generated Certificate Signing Request will be stored
* `-i ../IO_file/config.jsn` JSON config file to define your own Distiguished Name for the End-Device Certificate

Example `config.jsn`:

```json
{
	"CN":	"AWS IoT Certificate",
	"O":	"Infineon Technologies AG",
	"C":	"DE",
	"ST":	"Germany"
}
```

```console
pi@raspberrypi:~/personalize-optiga-trust-x/executables $ ./optiga_upload_crt -f /dev/i2c-1 -c certificate_in_der.der -o 0xE0E1
```
* `-f /dev/i2c-1` Path to the i2c device to which # Infineon's OPTIGA&trade; Trust X is connected
* `-c certificate_in_der.der` DER encoded certificate which you want to upload to the device
* `-0 0xE0E1` Optional parameter which defines in which Obejct ID to write the given certificate

In order to convert PEM encoded certificate into DER encoded certificate you can use the following command

```console
pi@raspberrypi:~/personalize-optiga-trust-x/executables $ openssl x509 -in certificate_in_pem.pem -inform PEM -out certificate_in_der.der -outform DER

```

## Generating Certificates for AWS IoT Core

Using this repository you can generate a new CSR which can be used to issue a new X.509 certificate signed by an AWS IoT Core Server.
For this you need to install an [AWS Command Line Interface](AWS Command Line Interface) which is availble as a packet for many platforms; e.g. it can be installed on Raspberry Pi by using the following [guidance](https://iotbytes.wordpress.com/aws-iot-cli-on-raspberry-pi/) [_Note: you need to have a valid AWS account for this_].

Assuming that you:
* Connected OPTIGA™ Trust X to the main board
  * if you OPTIGA™ Trust X board has reset and power control lines, you need to define them in the [pal_ifx_i2c_config.c](https://github.com/Infineon/optiga-trust-x/blob/7bb45810fe166e74683aa74fdd2394a1744c455e/pal/linux/pal_ifx_i2c_config.c#L46) file
  * An example connection with OPTIGA™ Trust X Evaluation Kit Adapter and RPi3 is following (OPTIGA™ Trust X on the left side, RPi3 on the right side):
    * VDD 3.3v [Pin# 37] - 3.3v PWR [Pin# 1]
    * SDA [Pin# 31] - I2C1 SDA [Pin# 3]
    * SCL [Pin# 29] - I2C1 SCL [Pin# 5]
    * RST [Pin# 27] - RST [Pin# 11]
    * VCC [Pin# 26] - 3.3v VCC [Pin# 13]
    * GND [Pin# 35] - GND [Pin# 39]
    * VCC line is required to control whether the security chip will be powered up or not.
* Have AWS CLI interface on your RPi
* Have executables available after building the code from sources as describe above 

```console
pi@raspberrypi:~/personalize-optiga-trust-x/executables $ sudo ./optiga_generate_csr -f /dev/i2c-1 -o ../IO_files/optiga.csr -i ../IO_files/config.jsn
Data read:
{
        "CN":   "AWS IoT Certificate",
        "O":    "Infineon Technologies AG",
        "C":    "DE",
        "ST":   "Germany"
}
CN=AWS IoT Certificate,O=Infineon Technologies AG,C=DE,ST=Germany
OPTIGA(TM) Trust X initialized.
Keypair generated.
Public key is
04A9A8AADE3AED513FBCFFDC276E89F245B70B380B3D9DB81F19BD3A56C8C11889B963582D2CFCC383229DF708C5060C3DE8B1F9F13E1FDAEE901330B117EF
  . Checking subject name...
  . Loading the private key ...
  . Writing the certificate request ...
OPTIGA(TM) Trust X Signature generation
304502205C4F90D147D511E3A36445E35BC251EA9EDD02E712B36D8EA7E8677F85EDDBB2022100F7630F847048CAFBC3D04285F3A229E4579478E23DC9855649997E0BD310 Size 71
ok
```

```console
pi@raspberrypi:~/personalize-optiga-trust-x/executables $ cd ../IO_files
pi@raspberrypi:~/personalize-optiga-trust-x/IO_files $ aws iot create-certificate-from-csr --region <your-region-eg-us-east-2> --certificate-signing-request file://optiga.csr --set-as-active
{
    "certificateArn": "arn:aws:iot:us-east-2:<account-id>:cert/2a8dc85a6c1c9e54446c96b1156505713f1204589e98082a21dd77b526ddc649",
    "certificatePem": "-----BEGIN CERTIFICATE-----\nMIIC0DCCAbigAwIBAgIUUHauGeCjmAZ1A5FfTlg0tdqplAYwDQYJKoZIhvcNAQEL\nBQAwTTFLMEkGA1UECwxCQW1hem9uIFdlYiBTZXJ2aWNlcyBPPUFtYXpvbi5jb20g\nSW5jLiBMPVNlYXR0bGUgU1Q9V2FzaGluZ3RvbiBDPVVTMB4XDTE4MTIwMzExMzIx\nMloXDTQ5MTIzMTIzNTk1OVowYDEcMBoGA1UEAxMTQVdTIElvVCBDZXJ0aWZpY2F0\nZTEhMB8GA1UEChMYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMQswCQYDVQQGEwJE\nRTEQMA4GA1UECBMHR2VybWFueTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKmo\nqt467VE/vP/cJ26J8kW3CzgLPZ24Hxm9OlbgcMjBGIm5Y1gtLPzDgyKd9wjFBgw9\n6LH58T4f2u6QEzCxF++jYDBeMB8GA1UdIwQYMBaAFJBlzDdR/Bj38EHXlSbFxD8B\nBoY8MB0GA1UdDgQWBBQuV99UXBw8gKzEATJYYmTqOgXXJDAMBgNVHRMBAf8EAjAA\nMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAEZDlgBfXeB+uO8bq\nTozU7Em8sSjSh7S7JoTH0BYR+7/Y4BX/ENEF3Pj3LgQfs2ybG6bY4SawGL7J+J5Z\neZbt1ycOJFTanzJcLdid0CjLYFmzJM5doOac2r4Q0fXspx5Cc7tO2ZLtkeIqIi8C\nc5kCgy7NY2cR6okuOzC+hf1OXnRfcTmxidN/r958GKbav+Q1FTSUNUMJgje/xkB+\nZV8QgfYgQlC58D1nqIK4y9t/0qIpUO0bgfSJSyjw6KcC3Hu8GdLUVbI1WnGlvGYj\nph3JvHrhAcBP4ryT4jl7r+ZazJdeo7dF9nJgjQtXduiknF/yVEzqrCYrKxLPC7WD\nIsRITg==\n-----END CERTIFICATE-----\n",
    "certificateId": "2a8dc85a6c1c9e54446c96b1156505713f1204589e98082a21dd77b526ddc649"
}
```

```console
pi@raspberrypi:~/personalize-optiga-trust-x/IO_files $ aws iot describe-certificate --region <your-region-eg-us-east-2> --certificate-id 2a8dc85a6c1c9e54446c96b1156505713f1204589e98082a21dd77b526ddc649 --output text --query certificateDescription.certificatePem > optiga.pem
```

```console
pi@raspberrypi:~/personalize-optiga-trust-x/IO_files $ cat optiga.pem
-----BEGIN CERTIFICATE-----
MIIC0DCCAbigAwIBAgIUUHauGeCjmAZ1A5FfTlg0tdqplAYwDQYJKoZIhvcNAQEL
BQAwTTFLMEkGA1UECwxCQW1hem9uIFdlYiBTZXJ2aWNlcyBPPUFtYXpvbi5jb20g
SW5jLiBMPVNlYXR0bGUgU1Q9V2FzaGluZ3RvbiBDPVVTMB4XDTE4MTIwMzExMzIx
MloXDTQ5MTIzMTIzNTk1OVowYDEcMBoGA1UEAxMTQVdTIElvVCBDZXJ0aWZpY2F0
ZTEhMB8GA1UEChMYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMQswCQYDVQQGEwJE
RTEQMA4GA1UECBMHR2VybWFueTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKmo
qt467VE/vP/cJ26J8kW3CzgLPZ24Hxm9OlbgcMjBGIm5Y1gtLPzDgyKd9wjFBgw9
6LH58T4f2u6QEzCxF++jYDBeMB8GA1UdIwQYMBaAFJBlzDdR/Bj38EHXlSbFxD8B
BoY8MB0GA1UdDgQWBBQuV99UXBw8gKzEATJYYmTqOgXXJDAMBgNVHRMBAf8EAjAA
MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAEZDlgBfXeB+uO8bq
TozU7Em8sSjSh7S7JoTH0BYR+7/Y4BX/ENEF3Pj3LgQfs2ybG6bY4SawGL7J+J5Z
eZbt1ycOJFTanzJcLdid0CjLYFmzJM5doOac2r4Q0fXspx5Cc7tO2ZLtkeIqIi8C
c5kCgy7NY2cR6okuOzC+hf1OXnRfcTmxidN/r958GKbav+Q1FTSUNUMJgje/xkB+
ZV8QgfYgQlC58D1nqIK4y9t/0qIpUO0bgfSJSyjw6KcC3Hu8GdLUVbI1WnGlvGYj
ph3JvHrhAcBP4ryT4jl7r+ZazJdeo7dF9nJgjQtXduiknF/yVEzqrCYrKxLPC7WD
IsRITg==
-----END CERTIFICATE-----
```

```console
pi@raspberrypi:~/personalize-optiga-trust-x/IO_files $ openssl x509 --in optiga.pem --inform PEM --out optiga.der --outform DER
```

```console
pi@raspberrypi:~/personalize-optiga-trust-x/IO_files $ sudo ../executables/optiga_upload_crt -f /dev              /i2c-1 -c optiga.der
OPTIGA(TM) Trust X initialized.

********************    Certificate read        ********************
Length: 724

********************    Parsing certificate     ********************
cert. version     : 3
serial number     : 50:76:AE:19:E0:A3:98:06:75:03:91:5F:4E:58:34:B5:DA:A9:94:06
issuer name       : OU=Amazon Web Services O=Amazon.com Inc. L=Seattle ST=Washington C=US
subject name      : CN=AWS IoT Certificate, O=Infineon Technologies AG, C=DE, ST=Germany
issued  on        : 2018-12-03 11:32:12
expires on        : 2049-12-31 23:59:59
signed using      : RSA with SHA-256
EC key size       : 256 bits
basic constraints : CA=false
key usage         : Digital Signature

********************    END     ********************

********************    Writing certificate     ********************

Certificate successfully written

********************    END     ********************
```


## Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
