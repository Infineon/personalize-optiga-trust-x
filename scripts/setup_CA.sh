#!/bin/bash

#This script creates a folder and file structure for a root and an intermediate Certificate signing authority for use with the OpenSSL commandline tools
#It is recommended to use at least one intermediate CA which signs the Object certificates, itself is signed by the root-CA.
#Loosing or loosing access to the root-certificate or the root-key will make validating signed certificates impossible, so be careful with handling it


#Reading arguments on script-call
serial=1000
while getopts ":d:r:i:h" opt; do
	case $opt in
		d)
			directory=$OPTARG
			;;
		r)
			root_config=$OPTARG
			;;
		i)
			intermediate_config=$OPTARG
			;;
		h)
			echo "Help:"
			echo "-d	Path to directory you want the structure to start with"
			echo "		If nothing specified, /root/ will be used"
			echo "-r	Path to Root-CA config file"
			echo "-i	Path to Intermediate-CA config file"
			echo "ROOT PRIVILEGES ARE REQUIRED FOR THIS SCRIPT"
			exit -1
			;;
		:)
			echo "Option -$OPTARG requires an argument" >&2
			exit -1
			;;
		\?)
			echo "Invalid option: -$OPTARG" >&2
			echo "Enter -h for help"
			exit -1
	esac
done

#Checking if arguments read are correct

if ! [ -d $directory ] || [ -z $directory ]
then
	directory=/root
fi
if ! [ -e $root_config ] || [ -z $root_config ]
then
	echo "No root-CA config file detected"
	echo "Enter -h for help"
	exit -1
fi
if ! [ -e $intermediate_config ] || [ -z $intermediate_config ]
then
	echo "No intermediate-CA config file detected"
	echo "Enter -h for help"
	exit -1
fi

#Building root-CA structure
	#Creating folder- and file-structure
		echo "Creating root structure..."
		mkdir $directory/ca
		cd $directory/ca
		mkdir certs crl newcerts private
		chmod 700 private
		touch index.txt
		echo $serial > serial
	#Copying config-file
		cp $root_config ./
		config=${root_config##*/}
	#Generating private Key and encrypting it
		echo "You will now be asked a password for AES256-encrypting your private key."
		echo "Be careful to remember it, or otherwise data you sign it with will be lost."
		#Generation 								#encrypting
		openssl ecparam -name prime256v1 -genkey | openssl ec -aes256 -out private/ca.key.pem
		chmod 400 private/ca.key.pem
	#Validationtime of Root-Certificate
		echo "Please enter an amount of days the root-certificate will be vaild for"
		read -p "Recommended value: 7300	" days_valid
	#Creating root-certificate
		echo "Creating root certificate..."
		openssl req -config $config -key private/ca.key.pem -new -x509 -days $days_valid -sha256 -extensions v3_ca -out certs/ca.cert.pem
		chmod 444 certs/ca.cert.pem
	#Converting pem-Certificate into der-Certificate
		openssl x509 -in certs/ca.cert.pem -out certs/ca.cert.der -outform DER
	#Viewing certificate
		openssl x509 -noout -text -in certs/ca.cert.pem

#Building intermediate-CA structure
	#Creating folder- and file-structure
		echo "Creating intermediate structure..."
		mkdir intermediate
		cd intermediate
		mkdir certs crl csr newcerts private
		chmod 700 private
		touch index.txt
		echo $serial > serial
		echo 1000 > crlnumber
	#Copying config-file
		cp $intermediate_config ./
		i_config=${intermediate_config##*/}
	#Generating private Key and encrypting it (if asked)
		echo "Generating keypair..."
		openssl ecparam -name prime256v1 -genkey -noout -out private/intermediate.key.pem
		read -p "Do you want to encrypt your keypair? [Y/n]" answer
		if [ $answer != n ] && [ $answer != N ]
		then 
			openssl ec -aes256 -in private/intermediate.key.pem -out private/intermediate.key.pem
		fi
		chmod 400 private/intermediate.key.pem
	#Requesting CSR
		openssl req -config $i_config -new -sha256 -key private/intermediate.key.pem -out csr/intermediate.csr.pem
		echo "Please enter an amount of days the intermediate_certificate will be valid for"
		read -p "Recommended Value: 3560	" days_valid
		echo "Creating intermediate certificate..."
		cd ../
	#Signing intermediate-csr with root-key and generating intermediate-certificate
		openssl ca -config $config -extensions v3_intermediate_ca -days $days_valid -in intermediate/csr/intermediate.csr.pem -out intermediate/certs/intermediate.cert.pem
		cd intermediate/
		chmod 444 certs/intermediate.cert.pem
	#Viewing certificate	
		openssl x509 -noout -text -in certs/intermediate.cert.pem
	#Converting pem-Certificate into der-Certificate
		openssl x509 -in certs/intermediate.cert.pem -out certs/intermediate.cert.der -outform DER
	#creating certificate chain
		echo "Creating certificate chain..."
		cat certs/intermediate.cert.pem ../certs/ca.cert.pem > certs/ca-chain.cert.pem
		chmod 444 certs/ca-chain.cert.pem
echo "Script returned successful"
