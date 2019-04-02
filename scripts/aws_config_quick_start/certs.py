#!/usr/bin/env python

import boto3
import json
import subprocess
import os
import sys
import shlex
import platform

class Certificate():

    def __init__(self, certId = ''):
        self.id = certId
        self.arn = ''
        self.client = boto3.client('iot')
        if (self.id != ''):
            result = self.client.describe_certificate(certificateId=self.id)
            self.arn = result['certificateDescription']['certificateArn']

    def __gencsr_linux__(self, exepath, cert_name, i2cDev, privateKeyOid):
        csr_fn = cert_name + '.csr'
        csrconf_fn = cert_name + '.jsn'
        try:
            subprocess.check_call( shlex.split(
                'sudo {0}/optiga_generate_csr -f {1} -p {2} -o {3} -i {4}'.format( 
                exepath, i2cDev, privateKeyOid, csr_fn, csrconf_fn)))
        except subprocess.CalledProcessError:
            print("Failed to generate a CSR using the OPTIGA(TM) Trust")
            sys.exit(1)

    def __gencsr_libusb__(self, exepath, cert_name, privateKeyOid):
        csr_fn = cert_name + '.csr'
        csrconf_fn = cert_name + '.jsn'

        try:
            subprocess.check_call(shlex.split( 
                '{0}/optiga_generate_csr -p {1} -o {2} -i {3}'.format( 
                exepath, privateKeyOid, csr_fn, csrconf_fn)))
        except subprocess.CalledProcessError:
            print("Failed to generate a CSR using the OPTIGA(TM) Trust")
            sys.exit(1)
    
    def __uploadcrt_linux__(self, exepath, i2cDev, certificateOid):
        try:
            subprocess.check_call(shlex.split(
            'sudo {0}/optiga_upload_crt -f {1} -c {2}.pem -o {3}'.format(exepath, i2cDev, self.id, certificateOid)))
        except subprocess.CalledProcessError:
            print("Failed to write back newly generated certificate into the OPTIGA(TM) Trust X")
            sys.exit(1)

    def __uploadcrt_libusb__(self, exepath, certificateOid):
        try:
            subprocess.check_call(shlex.split(
            '{0}/optiga_upload_crt -c {1}.pem -o {2}'.format(exepath, self.id, certificateOid)))
        except subprocess.CalledProcessError:
            print("Failed to write back newly generated certificate into the OPTIGA(TM) Trust X")
            sys.exit(1)

    def create(self, exepath = '', i2cDev = '', privateKeyOid = '0xE0F1', certificateOid = '0xE0E1'):
        cert_name = 'aws_optiga_cert'
        csr_fn = cert_name + '.csr'
        csrconf_fn = cert_name + '.jsn'
        
        assert exepath != '', "Please specify a path to OPTIGA(TM) bin; e.g. ../../bin/linux_win32_x86"
        assert self.exists() == False, "Cert already exists"

        exepath = "{0}/{1}".format("../../bin/", exepath)
		
        if i2cDev == '':
            self.__gencsr_libusb__(exepath, cert_name, privateKeyOid)
        else:
            self.__gencsr_linux__(exepath, cert_name, i2cDev, privateKeyOid)

        with open(csr_fn, 'r') as myfile:
            csr = myfile.read()
        myfile.close()

        cert = self.client.create_certificate_from_csr(certificateSigningRequest=csr, setAsActive=True)
        self.id = cert["certificateId"]
        self.arn = cert["certificateArn"]
        cert_pem_file = open(self.id + '.pem', "w")
        cert_pem_file.write(cert["certificatePem"])
        cert_pem_file.close()
            
        if i2cDev == '':
            self.__uploadcrt_libusb__(exepath, certificateOid)
        else:
            self.__uploadcrt_linux__(exepath, i2cDev, certificateOid)
        
        # Clean temp files
        os.remove(csr_fn)
        os.remove(self.id + '.pem')
        
        return cert

    def delete(self):
        cert_not_found = True
        # Detach Policies attached to the cert
        policies_attached = self.list_policies()
        for policy in policies_attached:
            self.detach_policy(policy['policyName'])

        # Detach Things attached to the cert
        things_attached = self.list_things()
        for thing in things_attached:
            self.detach_thing(thing)

        # Update the status of the certificate to INACTIVE
        try:
            self.client.update_certificate(certificateId=self.id,
                newStatus='INACTIVE')
            cert_not_found = False
        except self.client.exceptions.ResourceNotFoundException:
            cert_not_found = True
            return cert_not_found

        # Delete the certificate
        try:
            self.client.delete_certificate(certificateId=self.id)
            cert_not_found = False
        except self.client.exceptions.ResourceNotFoundException:
            cert_not_found = True
        return cert_not_found

    def exists(self):
        if self.id == '':
            return False
        else:
            return True

    def get_arn(self):
        return self.arn

    def list_policies(self):
        policies = self.client.list_principal_policies(principal=self.arn)
        policies = policies['policies']
        return policies

    def attach_policy(self, policy_name):
        self.client.attach_policy(policyName=policy_name,
            target=self.arn)

    def detach_policy(self, policy_name):
        self.client.detach_policy(policyName=policy_name,
            target=self.arn)

    def list_things(self):
        things = self.client.list_principal_things(principal=self.arn)
        things = things['things']
        return things

    def attach_thing(self, thing_name):
        self.client.attach_thing_principal(thingName=thing_name,
            principal=self.arn)

    def detach_thing(self, thing_name):
        self.client.detach_thing_principal(thingName=thing_name,
            principal=self.arn)
