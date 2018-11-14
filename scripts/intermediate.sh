#!/bin/bash
serial=1000
while getopts ":d:r:i:h" opt; do
        case $opt in
                d)
                        directory=$OPTARG
                        ;;
                i)
                        intermediate_config=$OPTARG
                        ;;
                h)
                        echo "Help:"
                        echo "-d        Path to directory you want the structure to start with"
                        echo "          If nothing specified, /root/ will be used"
                        echo "-r        Path to Root-CA config file"
                        echo "-i        Path to Intermediate-CA config file"
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
        directory=.
fi
if ! [ -e $intermediate_config ] || [ -z $intermediate_config ]
then
        echo "No intermediate-CA config file detected"
        echo "Enter -h for help"
        exit -1
fi
#Building intermediate-CA structure
echo "Creating intermediate structure..."
cd $directory
mkdir intermediate_server
cd intermediate_server
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo $serial > serial
echo 1000 > crlnumber
cp $intermediate_config ./
i_config=${intermediate_config##*/}
echo "Generating keypair..."
openssl ecparam -name prime256v1 -genkey -noout -out private/intermediate.key.pem
read -p "Do you want to encrypt your keypair? [Y/n]" answer
if [ $answer != n ] && [ $answer != N ]
then 
        openssl ec -aes256 -in private/intermediate.key.pem -out private/intermediate.key.pem
fi
chmod 400 private/intermediate.key.pem
openssl req -config $i_config -new -sha256 -key private/intermediate.key.pem -out csr/intermediate.csr.pem
echo "Please enter an amount of days the intermediate_certificate will be valid for"
read -p "Recommended Value: 3560        " days_valid
echo "Creating intermediate certificate..."
cd ../
openssl ca -config /home/pi/Project_Trust/skripts/prime256/ca/intermediate/inter_openssl.cnf -extensions v3_intermediate_ca -days $days_valid -in intermediate_server/csr/intermediate.csr.pem -out intermediate_server/certs/intermediate.cert.pem
cd intermediate_server/
chmod 444 certs/intermediate.cert.pem
openssl x509 -noout -text -in certs/intermediate.cert.pem
echo "Creating certificate chain..."
cat certs/intermediate.cert.pem ../certs/ca.cert.pem > certs/ca-chain.cert.pem
chmod 444 certs/ca-chain.cert.pem
openssl ecparam -name prime256v1 -genkey -noout -out private/DBserver.key.pem
openssl req -config $i_config -key private/DBserver.key.pem -new -sha256 -out csr/DBserver.csr.pem
openssl ca -config $i_config -extensions server_cert -notext -md sha256 -in csr/DBserver.csr.pem -out certs/DBserver.cert.pem
cat certs/DBserver.cert.pem certs/intermediate.cert.pem ../certs/intermediate.cert.pem > certs/DB_chain.cert.pem
echo "Script returned successful"

