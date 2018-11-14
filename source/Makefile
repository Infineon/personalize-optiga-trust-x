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

#Include build congiguration, compiler to be used, file name/directory definitions
-include Config.mk

ROOT_DIR = .

BIN_DIR =				$(ROOT_DIR)/../executables
BUILD_DIR =				$(ROOT_DIR)/build

OPTIGA_CORE_OBJECTS =	$(patsubst %.c, $(BUILD_DIR)/%.o, $(SOURCES))
GEN_CSR_OBJECTS =		$(patsubst %.c, $(BUILD_DIR)/%.o, $(GEN_CSR_SOURCES))

.PHONY: dir all clean

all: dir $(BIN_DIR)/optiga_generate_csr

#Make application note

#Create Directories for binaries and build
dir:
	$(MKDIR) -p $(BUILD_DIR)
	$(MKDIR) -p $(BIN_DIR)

$(BUILD_DIR)/%.o: %.c
	@echo Compiling $<
	@mkdir -p $(dir $@)
	@$(CC) $(CCFLAGS) $(INCLUDES) $(GEN_CSR_INCLUDES) -c $< -o $@

$(BIN_DIR)/optiga_generate_csr: $(OPTIGA_CORE_OBJECTS) $(GEN_CSR_OBJECTS)
	@echo Linking $@
	$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

	
#Clean
clean: 
	$(CLEAN) -rf $(BUILD_DIR) $(BIN_DIR)
