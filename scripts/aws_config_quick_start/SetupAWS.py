#!/usr/bin/env python

import argparse
import json
import thing
import policy
import certs
import misc
import boto3
import sys
import os

def check_aws_configuration():
    mysession = boto3.session.Session()
    if not (mysession._session._config['profiles']):
        print("AWS not configured. Please run `aws configure`.")
        sys.exit(1)


def prereq():
    with open('configure.json') as file:
        json_text = json.load(file)
        aws_config = json_text["aws_config"]
        optiga_config = json_text["optiga_trust_config"]

    # Create a Certificate
    cert_obj = certs.Certificate()
    result = cert_obj.create(optiga_config['executable_path'],
                             optiga_config['i2c_device'],
                             optiga_config['privatekey_objectid'],
                             optiga_config['certificate_objectid'])

    # Create a Thing if doesn't exist
    thing_name = aws_config['thing_name']
    thing_obj = thing.Thing(thing_name)
    if not thing_obj.exists():
        thing_obj.create()

        # Store certId
        cert_id = result['certificateId']
        cert_id_filename = thing_name + '_cert_id_file'
        cert_id_file = open(cert_id_filename, 'w')
        cert_id_file.write(cert_id)
        cert_id_file_path = os.path.abspath(cert_id_filename)
        os.chmod(cert_id_file_path, 0o444)
        cert_id_file.close()

        # Store cert_pem as file
        cert_pem = result['certificatePem']
        cert_pem_filename = thing_name + '_cert_pem_file'
        cert_pem_file = open(cert_pem_filename, 'w')
        cert_pem_file.write(cert_pem)
        cert_pem_file_path = os.path.abspath(cert_pem_filename)
        os.chmod(cert_pem_file_path, 0o444)
        cert_pem_file.close()

    # Create a Policy if doesn't exist
    policy_obj = policy.Policy(aws_config['policy_name'])
    if not policy_obj.exists():
        policy_document = misc.create_policy_document()
        policy_obj.attach_rules(policy_document)
        policy_obj.create()

    # Attach certificate to Thing
    cert_obj.attach_thing(aws_config['thing_name'])

    # Attach policy to certificate
    cert_obj.attach_policy(aws_config['policy_name'])

def update_credential_file():
    with open('configure.json') as file:
        json_text = json.load(file)
        aws_config = json_text["aws_config"]

    thing_name = aws_config['thing_name']

    # Read cert_pem from file
    cert_pem_filename = thing_name + '_cert_pem_file'
    try:
        cert_pem_file = open(cert_pem_filename, 'r')
    except IOError:
        print("%s file not found. Run prerequisite step"%cert_pem_filename)
        sys.exit(1)
    else:
        cert_pem = cert_pem_file.read()

def delete_prereq():
    with open('configure.json') as file:
        json_text = json.load(file)
        aws_config = json_text["aws_config"]

    # Delete Thing
    thing_name = aws_config['thing_name']
    thing_obj = thing.Thing(thing_name)
    thing_obj.delete()

    # Delete certificate
    cert_id_filename = thing_name + '_cert_id_file'
    cert_id_file = open(cert_id_filename, 'r')
    cert_id =  cert_id_file.read()
    cert_obj = certs.Certificate(cert_id)
    cert_obj.delete()
    os.remove(cert_id_filename)

    # Delete cert_pem file and private_key_pem file
    cert_pem_filename = thing_name + '_cert_pem_file'
    os.remove(cert_pem_filename)

    # Delete policy
    policy_name = thing_name + '_amazon_freertos_policy'
    policy_obj = policy.Policy(policy_name)
    policy_obj.delete()


def setup():
    prereq()
    update_credential_file()

def cleanup():
    delete_prereq()

def list_certificates():
    client = boto3.client('iot')
    certs = client.list_certificates()['certificates']
    print(certs)

def list_things():
    client = boto3.client('iot')
    things = client.list_things()['things']
    print(things)

def list_policies():
    client = boto3.client('iot')
    policies = client.list_policies()['policies']
    print(policies)

if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser()
    sub_arg_parser = arg_parser.add_subparsers(help='Available commands',
        dest='command')
    setup_parser = sub_arg_parser.add_parser('setup', help='setup aws iot')
    clean_parser = sub_arg_parser.add_parser('cleanup', help='cleanup aws iot')
    list_cert_parser = sub_arg_parser.add_parser('list_certificates',
        help='list certificates')
    list_thing_parser = sub_arg_parser.add_parser('list_things',
        help='list things')
    list_policy_parser = sub_arg_parser.add_parser('list_policies',
        help='list policies')
    prereq_parser = sub_arg_parser.add_parser('prereq',
        help='Setup Prerequisites for aws iot')
    update_creds = sub_arg_parser.add_parser('update_creds',
        help='Update credential files')
    delete_prereq_parser = sub_arg_parser.add_parser('delete_prereq',
        help='Delete prerequisites created')
    cleanup_creds_parser = sub_arg_parser.add_parser('cleanup_creds',
        help='Cleanup credential files')
    args = arg_parser.parse_args()

    check_aws_configuration()

    if args.command == 'setup':
        setup()
    elif args.command == 'cleanup':
        cleanup()
    elif args.command == 'list_certificates':
        list_certificates()
    elif args.command == 'list_things':
        list_things()
    elif args.command == 'list_policies':
        list_policies()
    elif args.command == 'prereq':
        prereq()
    elif args.command == 'delete_prereq':
        delete_prereq()
    elif args.command == 'cleanup_creds':
        cleanup_creds()
    else:
        print("Command does not exist")
