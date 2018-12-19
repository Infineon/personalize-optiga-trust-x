#
# \copyright
# MIT License
#
# Copyright (c) 2018 Infineon Technologies AG
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE
#
# \endcopyright
#
# \author Infineon Technologies AG
#
#Names of the output binaries

ROOT_DIR = .

# Directory with the Application Notes Framework for OPTIGA(TM) Trust X
OPTIGA_CORE_DIR = $(ROOT_DIR)/optiga_trust_x/optiga

# OPTIGA(TM) Trust X core source code files to be built
OPTIGA_SOURCES =    $(OPTIGA_CORE_DIR)/crypt/optiga_crypt.c \
					$(OPTIGA_CORE_DIR)/util/optiga_util.c \
					$(OPTIGA_CORE_DIR)/cmd/CommandLib.c \
					$(OPTIGA_CORE_DIR)/common/Logger.c \
					$(OPTIGA_CORE_DIR)/common/Util.c \
					$(OPTIGA_CORE_DIR)/comms/ifx_i2c/ifx_i2c.c \
					$(OPTIGA_CORE_DIR)/comms/ifx_i2c/ifx_i2c_config.c \
					$(OPTIGA_CORE_DIR)/comms/ifx_i2c/ifx_i2c_data_link_layer.c \
					$(OPTIGA_CORE_DIR)/comms/ifx_i2c/ifx_i2c_physical_layer.c \
					$(OPTIGA_CORE_DIR)/comms/ifx_i2c/ifx_i2c_transport_layer.c

# OPTIGA(TM) Trust X header file dependencies					
OPTIGA_INCLUDES =  -I$(OPTIGA_CORE_DIR)/include/

# Directory with the Platform Abstraction Layer (PAL) for OPTIGA(TM) Trust X
PAL_LINUX_DIR = 	$(ROOT_DIR)/optiga_trust_x/pal/linux

# Platform Abstraction Layer (PAL) source code files to be built
PAL_LINUX_SOURCES = $(OPTIGA_CORE_DIR)/comms/optiga_comms.c \
					$(PAL_LINUX_DIR)/pal.c \
					$(PAL_LINUX_DIR)/pal_gpio.c \
					$(PAL_LINUX_DIR)/pal_i2c.c \
					$(PAL_LINUX_DIR)/pal_ifx_i2c_config.c \
					$(PAL_LINUX_DIR)/pal_os_event.c \
					$(PAL_LINUX_DIR)/pal_os_lock.c \
					$(PAL_LINUX_DIR)/pal_os_timer.c 

# Platform Abstraction Layer (PAL) header file dependencies					
PAL_LINUX_INCLUDES =-I$(OPTIGA_CORE_DIR)/include/pal/ \
					-I$(PAL_LINUX_DIR)/
					
# Directory with the Platform Abstraction Layer (PAL) for OPTIGA(TM) Trust X
PAL_LIBUSB_DIR = 	$(ROOT_DIR)/optiga_trust_x/pal/libusb

# Platform Abstraction Layer (PAL) source code files to be built
PAL_LIBUSB_SOURCES =$(PAL_LIBUSB_DIR)/optiga_comms_ifx_i2c_usb.c \
					$(PAL_LIBUSB_DIR)/pal_common.c \
					$(PAL_LIBUSB_DIR)/pal.c \
					$(PAL_LIBUSB_DIR)/pal_gpio.c \
					$(PAL_LIBUSB_DIR)/pal_i2c.c \
					$(PAL_LIBUSB_DIR)/pal_ifx_usb_config.c \
					$(PAL_LIBUSB_DIR)/pal_os_event.c \
					$(PAL_LIBUSB_DIR)/pal_os_lock.c \
					$(PAL_LIBUSB_DIR)/pal_os_timer.c
					#$(PAL_LIBUSB_DIR)/usb_lib_loader.c

# Platform Abstraction Layer (PAL) header file dependencies					
PAL_LIBUSB_INCLUDES =-I$(OPTIGA_CORE_DIR)/include/pal/ \
					 -I$(PAL_LIBUSB_DIR)/include/
					
##############################################################

# Directory with JSON parser files
JSON_DIR = 			$(ROOT_DIR)/json_parser

# JSON parser source code files to be built
JSON_SOURCES =		$(JSON_DIR)/cJSON.c \
					$(JSON_DIR)/JSON_parser.c
					
# JSON parser includes
JSON_INCLUDES =		-I$(JSON_DIR)

# Directory with the Generate CSR Application
GEN_CSR_DIR = 		$(ROOT_DIR)

# Generate CSR application source code files to be built
GEN_CSR_SOURCES=	$(GEN_CSR_DIR)/optiga_generate_csr.c 

# Generate CSR application header file dependencies					
GEN_CSR_INCLUDES=	-I$(GEN_CSR_DIR) \
                    -I$(ROOT_DIR)/mbedtls-2.6.0/include

# Directory with the Upload Generated Certificate
UPLOAD_CRT_DIR = 	$(ROOT_DIR)

# Generate CSR application source code files to be built
UPLOAD_CRT_SOURCES=	$(UPLOAD_CRT_DIR)/optiga_upload_crt.c 

# Generate CSR application header file dependencies					
UPLOAD_CRT_INCLUDES=-I$(UPLOAD_CRT_DIR) \
                    -I$(ROOT_DIR)/mbedtls-2.6.0/include
					
CCFLAGS =           -g -Wall -DPAL_OS_HAS_EVENT_INIT

LDFLAGS =           -L$(ROOT_DIR)/mbedtls-2.6.0/library/ 
LDLIBS  =           -lmbedtls -lmbedx509 -lmbedcrypto

ifeq ($(MAKECMDGOALS), libusb)
LDFLAGS +=          -L$(PAL_LIBUSB_DIR)/include/
LDLIBS +=           -lusb-1.0 -lm
endif

#############################################################################

# Common source code to be built
SOURCES := 			$(OPTIGA_SOURCES)  \
					$(JSON_SOURCES)

# Common header file dependencies
INCLUDES := 		$(OPTIGA_INCLUDES) \
					$(JSON_INCLUDES)

#Commands, compiler configuration
#CC = C:\SysGCC\Raspberry\bin\arm-linux-gnueabihf-gcc.exe 
CLEAN = rm
MKDIR = mkdir
COPY = cp

