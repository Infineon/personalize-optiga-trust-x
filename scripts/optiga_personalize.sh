#!/bin/bash
#Read parameters
while getopts ":c:o:i:e:h" opt; do
	case $opt in
		c)
			ca_config_path=$OPTARG
			;;
		o)
			output=$OPTARG
			;;
		i)
			config_path=$OPTARG
			;;
		e)	exec_path=$OPTARG
			;;
		h)
			echo "Help:"
			echo "-c	Path to config-file of the CA the certificate should be signed with"
			echo "-o	Path to a folder where output-files of this script will be stored"
			echo "-i	Path to the file wich contains the input-data for the CSR"
			echo "		File must be written with/in JSON"
			echo "-e	Path to the directory of executable files (optiga_create_csr & optiga_write_cert)"
			exit -1
			;;
		\?)
			echo "Invalid option: -$OPTARG" >&2
			echo "Enter -h for help"
			exit -1
			;;
		:)
			echo "Option -$OPTARG requires an argument" >&2
			exit -1
			;;
	esac
done
#Check if input-Parameters are valid
if ! [ -e $ca_config_path ]
then
	echo "No CA config-file is specified. Please use -h for more information"
	exit -1
fi
if ! [ -d $output ]
then
	echo "No output-folder specified"
	echo "Current folder will be used"
	output=.
fi
if ! [ -e $config_path ]
then
	echo "No config-file specified. Please use -h for more information"
	exit -1
fi
if ! [ -d $exec_path ]
then
	echo "No executable path specified. Current folder will be used!"
	exec_path=.
fi
#Use function optiga_create_csr to generate CSR
$exec_path/optiga_create_csr -o $output/optiga.csr -i $config_path
if [ $? != 0 ]
then
	echo "optiga_create_csr returned!"
	echo "Creating CSR failed!"
	exit -1
fi
#get path of anchor-certificate
anchor=${ca_config_path%/*}
#sign CSR
openssl ca -config $ca_config_path -extensions usr_cert -md sha256 -in $output/optiga.csr -out $output/certificate.pem
#convert cert.pem to cert.der
openssl x509 -in $output/certificate.pem -out $output/certificate.der -outform DER
#write back certificate + trust anchor
$exec_path/optiga_write_cert -c $output/certificate.der -t $anchor/certs/*.cert.der
if [ $? != 0 ]
then
	echo "optiga_write_cert returned!"
	echo "Writing certificate failed!"
	exit -1
fi

