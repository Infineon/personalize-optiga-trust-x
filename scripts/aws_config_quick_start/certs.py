#!/usr/bin/env python

import boto3
import json
import os

class Certificate():

    def __init__(self, certId = ''):
        self.id = certId
        self.arn = ''
        self.client = boto3.client('iot')
        if (self.id != ''):
            result = self.client.describe_certificate(certificateId=self.id)
            self.arn = result['certificateDescription']['certificateArn']

    def create(self, i2cDev = '/dev/i2c-1', privateKeyOid = '0xE0F1', certificateOid = '0xE0E1'):
        cert_prefix = 'aws_optiga_cert'
        csr_fn = cert_prefix + '.csr'
        
        assert self.exists() == False, "Cert already exists"
        
        try:
            os.system('sudo ../../executables/optiga_generate_csr' +
                        ' -f' + i2cDev + 
                        ' -p ' + privateKeyOid +
                        ' -o ' + csr_fn +
                        ' -i ./aws_cert_config.jsn')
        except:
            print("Failed to generate a CSR with OPTIGA(TM) Trust X")
            sys.exit(1)
        
        with open(csr_fn, 'r') as myfile:
            csr = myfile.read()
        myfile.close()

        cert = self.client.create_certificate_from_csr(certificateSigningRequest=csr, setAsActive=True)
        self.id = cert["certificateId"]
        self.arn = cert["certificateArn"]
        cert_pem_file = open(self.id + '.pem', "w")
        cert_pem_file.write(cert["certificatePem"])
        cert_pem_file.close()

        try:
            os.system('openssl x509' + 
                        ' --in ' + self.id + '.pem' + ' --inform PEM' + 
                        ' --out ' + self.id + '.der' + ' --outform DER')
            os.system('sudo ../../executables/optiga_upload_crt' + 
                        ' -f' + i2cDev +
                        ' -c ' + self.id + '.der' +
                        ' -o ' + certificateOid)
        except:
            print("Failed to write back newly generated certificate into the OPTIGA(TM) Trust X")
            sys.exit(1)
        
        # Clean temp files
        os.remove(csr_fn)
        os.remove(self.id + '.pem')
        os.remove(self.id + '.der')
        
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
