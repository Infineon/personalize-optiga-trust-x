# This repository moved [here](https://github.com/Infineon/personalize-optiga-trust)

# Personalize your OPTIGA™ Trust X sample

## Description

This repository contains one of Application Notes for [OPTIGA™ Trust X](https://www.infineon.com/cms/en/product/security-smart-card-solutions/optiga-embedded-security-solutions/optiga-trust/optiga-trust-x-sls-32aia/) security chip.

* You can find more information about the security chip in the core [repository](https://github.com/Infineon/optiga-trust-x)
* You can find other Application Notes in the respective [repository](https://github.com/Infineon/appnotes-optiga-trust-x)

## Summary
In this guide you may find the following steps:
* How to issue your own self-signed CA certificate with openSSL
* How to generate a Certificate Signing Request (CSR) with OPTIGA™ Trust X and sign it with the CA
* How to generate an end-device certificate and write it back to one of available certificate slots on the device
* How to issue a certificate for an OPTIGA™ Trust X using CSR and your AWS IoT instance
* How to provision/register an OPTIGA™ Trust X on your AWS IoT instance

## Hardware and Software
For this application note you need to have:
* Either of the following:
  * Embedded Linux Platform with open GPIO and i2c interface
  * One of FTDI I2C Adapters availble on market
* OPTIGA™ Trust X which has opened i2c lines

* You can personalize your OPTIGA™ Trust Shield 2Go either via a direct communication to i2c interface on any embedded linux board: e.g. Raspberry Pi3 or via an OPTIGA™ Trust Perso Shield(link pending)
  * **via the direct I<sup>2</sup>C interface**
    * An example connection with OPTIGA™ Trust X Security Shield 2Go and RPi3 is below. Note: This setup is valid, if you want to provision the device using a direct i2c connection. Alternative you can use an FTDI USB/i2c converter for this.
![](https://github.com/Infineon/Assets/blob/master/Pictures/optiga_trust_x_rpi3_setup.jpg)

  * **via the OPTIGA™ Trust Perso Shield(link pending)**
    * In this case no special actions are required except for installation of the FTDI/libusb drivers
    * Windows
      * FTDI D2XX Direct [Drivers](https://www.ftdichip.com/Drivers/D2XX.htm)
      * Unplug and plugin your device
    * Linux; e.g. Debian based
      * `apt-get install libusb-1.0-0-dev libusb-1.0-0`
* AWS related settings:
  * Install Python 2.7.10 or later
  * Make sure the AWS CLI is installed on your system. For more information, see [Installing the AWS Command Line Interface](https://docs.aws.amazon.com/cli/latest/userguide/installing.html)
  * Run `aws configure` to configure the AWS CLI. For more information, see [Configuring the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html)
  * Use the following command to install the boto3 Python module: `$  pip install boto3`
* [Optional] Install [MSYS2](https://www.msys2.org/)
  * Install Git client by executing the `pacman -S git git-gui` command in the MSYS2 environment
  * _**Note: We recommend to use the 32bit version of the MSYS2 launcher, i.e. MSYS2 MinGW 32-bit**_ 


## [Optional] Build from sources

In order to obtain the sources we recommend to use following command:
```console
git clone --recursive https://github.com/Infineon/personalize-optiga-trust-x
```

Prior using the perso application note you need to build required bin from provided sources.
Copy this repository to your embedded system using any available method (USB stick, SSH transfer, SCP, etc.)
```console
pi@raspberrypi:~ $ cd personalize-optiga-trust-x/source
pi@raspberrypi:~/personalize-optiga-trust-x/source $ make rpi3|libusb
```

`rpi3` option is required when you have your security controller directly connected to your RPi3 machine via GPIOs, wheras `libusb` builds executables for the setup with the FTDI-I2C option
During the build process you should see console output as shown below
<details> 
  <summary> Built process of mbedTLS and OPTIGA Trust X library</summary>

```console
mkdir -p ./build
mkdir -p ./../bin
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
Linking ../bin/optiga_generate_csr
Compiling optiga_upload_crt.c
Linking ../bin/optiga_upload_crt
```
</details>

Your binaries are ready to be used and can be found in the folder bin in the root directory of your project

## Usage examples for binaries

```console

pi@raspberrypi:~/personalize-optiga-trust-x/bin/rpi3_linux_arm $ ./optiga_generate_csr -f /dev/i2c-1 -o optiga.csr -i ../../IO_files/config.jsn

```
* `-f /dev/i2c-1` Path to the i2c device to which # Infineon's OPTIGA&trade; Trust X is connected (Note: it might vary from paltform to platform)
* `-o optiga.csr` Path to a file, where a generated Certificate Signing Request will be stored
* `-i ../../IO_file/config.jsn` JSON config file to define your own Distiguished Name for the End-Device Certificate

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
pi@raspberrypi:~/personalize-optiga-trust-x/executables/rpi3_linux_arm $ ./optiga_upload_crt -f /dev/i2c-1 -c certificate_in_pem.pem -o 0xE0E1
```
* `-f /dev/i2c-1` Path to the i2c device to which # Infineon's OPTIGA&trade; Trust X is connected
* `-c certificate_in_der.der` DER encoded certificate which you want to upload to the device
* `-0 0xE0E1` Optional parameter which defines in which Obejct ID to write the given certificate


## Issue an X.509 certificate

* [Issuing Certificates with OpenSSL](https://github.com/Infineon/personalize-optiga-trust-x/wiki#issuing-certificates-with-openssl)
* [Issuing Certificates with AWS IoT Core](https://github.com/Infineon/personalize-optiga-trust-x/wiki#issuing-certificates-with-aws-iot-core)


## Contributing
Please read [CONTRIBUTING.md](https://github.com/Infineon/optiga-trust-x/blob/master/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
