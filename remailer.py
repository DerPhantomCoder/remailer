#!/bin/python3

import email
from email import policy
from email.parser import BytesFeedParser
from smtplib import SMTP
import logging
import argparse
import yaml
from dbm import gnu as gdbm
from os.path import exists
import time
import sys
import os
import re
import base64
import tempfile
import traceback
import unittest
import hmac
import hashlib

class Remailer:
    to_addr:str = None
    from_addr:str = None
    return_code:int = None
    last_exception = None
    log_messages:bool = False
    sender:str = None
    recipient:str = None

    EX_USAGE       = 64      #/* command line usage error */
    EX_DATAERR     = 65      #/* data format error */
    EX_NOINPUT     = 66      #/* cannot open input */
    EX_NOUSER      = 67      #/* addressee unknown */
    EX_NOHOST      = 68      #/* host name unknown */
    EX_UNAVAILABLE = 69      #/* service unavailable */
    EX_SOFTWARE    = 70      #/* internal software error */
    EX_OSERR       = 71      #/* system error (e.g., can't fork) */
    EX_OSFILE      = 72      #/* critical OS file missing */
    EX_CANTCREAT   = 73      #/* can't create (user) output file */
    EX_IOERR       = 74      #/* input/output error */
    EX_TEMPFAIL    = 75      #/* temp failure; user is invited to retry */
    EX_PROTOCOL    = 76      #/* remote error in protocol */
    EX_NOPERM      = 77      #/* permission denied */
    EX_CONFIG      = 78      #/* configuration error */

    trigger_string = 'anonymize'
    catchall_address = 'catchall'

    def init_log(self, log:str = None, level:int = None):
        try:
            if log is None:
                if 'log' in self.config:
                    filename = self.config['log']
                else:
                    filename = '/tmp/remailer.log'
            else:
                filename = log

            if level is None:
                if 'log_level' in self.config:
                    log_level = self.config['log_level']
                else:
                    log_level = logging.DEBUG
            else:
                log_level = level

            log_format='%(asctime)s - %(levelname)s - %(message)s'

            if debug == False:
                logging.basicConfig(format=log_format, filename=filename, level=log_level)
            else:
                logging.basicConfig(format=log_format, level=logging.DEBUG)

            return True
        except Exception as e:
            self.last_exception = e
            self.return_code = self.EX_TEMPFAIL
            return False

    def load_config(self, path: str):
        try:
            if path is not None:
                with open(path, "r") as f:
                    self.config = yaml.load(f, Loader=yaml.SafeLoader)

                if 'log_messages' in self.config:
                    self.log_messages = self.config['log_messages']

                return True

            else:
                self.return_code = self.EX_USAGE
                return False

        except PermissionError as e:
            self.return_code = self.EX_NOPERM
            self.last_exception = e
            logging.critical('Permission denied while opening %s', path)
            return False

        except Exception as e:
            self.return_code = self.EX_CONFIG
            self.last_exception = e
            logging.critical('Error while parsing %s', path)
            return False

    def lookup_forward(self, address: str = None):
        if address is not None:
            lookup_addr = address
        else:
            lookup_addr = self.to_addr

        try:
            with gdbm.open(self.config['map'], 'ruf') as db:
                
                if lookup_addr not in db:
                    if self.catchall_address not in db:
                        logging.error('Recipient not found in alias db, are you missing a catchall?: %s', lookup_addr)
                        self.return_code = self.EX_NOUSER
                        return False
                    else:
                        return db[self.catchall_address].decode()

                else:
                    return db[lookup_addr].decode()

        except PermissionError as e:
            self.return_code = self.EX_NOPERM
            self.last_exception = e
            logging.critical('Permission denied while opening %s', self.config['map'])
            return False

        except Exception as e:
            self.return_code = self.EX_IOERR
            self.last_exception = e
            return False

    def makedb(self):
        try:
            with gdbm.open(self.config['map'], 'n') as db:
                for line in sys.stdin:
                    (email_in, email_out) = line.split(':')
                    db[email_in.strip()] = email_out.strip()
                logging.info('Rebuilt alias db: %s entries added', len(db))

            return True

        except PermissionError as e:
            self.return_code = self.EX_NOPERM
            self.last_exception = e
            logging.critical('Permission denied while opening %s', self.config['map'])
            return False
            
        except Exception as e:
            self.return_code = self.EX_IOERR
            self.last_exception = e
            logging.critical('Error while building alias db')
            logging.critical(e)
            return False

    def detect_anonymized(self, message: email.message.EmailMessage):
        if 'To' in message:
            (name, addr) = email.utils.parseaddr(message['To'])

            result = re.match(r'(?P<box>[^+]+)\+(?P<extra>[^@]+)@(?P<domain>.+)', addr)

            if result:
                encoded_addr = result.group('extra').split('.')

                if len(encoded_addr) == 3:
                    (trigger, encoded_from, signature) = encoded_addr

                if trigger == self.trigger_string:
                    self.to_addr = str(result.group('box') + '@' + result.group('domain'))
                    self.from_addr = self.decode_addr(encoded_from)
                    if self.validate_signature(self.from_addr, base64.b64decode(signature)) != True:
                        logging.error('Signature validation failed for %s', addr)
                        self.return_code = self.EX_DATAERR
                        return None

                    return True

                else: #no trigger string match
                    return False

            else: #regex not matched
                self.to_addr = addr
                return False

        else: #no To header
            logging.error('No To address in message')
            return False

    def decode_addr(self, address: str):
        result = base64.b64decode(address).decode()
        return result

    def encode_addr(self, address: str):
        (name, addr) = email.utils.parseaddr(address)
        digest = base64.b64encode(self.sign_string(addr)).decode()
        encoded_addr = base64.b64encode(addr.encode()).decode()
        return encoded_addr + '.' + digest

    def sign_string(self, message: str):
        key = bytearray.fromhex(self.config['signing_key'])
        auth = hmac.new(key, message.encode(), hashlib.sha256)
        return auth.digest()

    def validate_signature(self, message: str, signature: bytes):
        digest = self.sign_string(message)
        return hmac.compare_digest(digest, signature)

    def strip_signature(self, content: str):
        buffer:str = ''
        prev_line:str = None

        for line in content.splitlines(keepends=True):
            # policy.SMTP doesn't fixup RFC non-compliant messages that
            # only have a newline line terminator
            # RFC states line terminator is CRLF
            if prev_line and prev_line.strip() == '':
                if line.strip() == '--':
                    break
            else:
                #debug formatting issues
                #if prev_line:
                #    print(prev_line.encode('utf-8').hex())
                buffer = buffer + line
        
            prev_line = line

        return buffer

    def forward_message(self, message: email.message.EmailMessage, recipient: str):
        #loop detection
        if 'X-Phantom-Remailer' in message:
            self.message = message
            logging.info('Detected an already forwarded message/redelivery attempt')
            return True

        if 'To' in message:
            (name, addr) = email.utils.parseaddr(message['To'])
            (to, domain) = addr.split('@')

            if to is not None and domain is not None:
                if 'From' in message:
                    encoded_from = self.encode_addr(message['From'])

                    reply_to_header = to + '+' + self.trigger_string + '.' + encoded_from + '@' + domain
                    if 'Reply-To' in message:
                        if message['Reply-To'] != reply_to_header:
                            message.add_header('X-Reply-To', message['Reply-To'])
                            message.replace_header('Reply-To', reply_to_header)

                    else:
                        message.add_header("Reply-To", reply_to_header)

            if 'Resent-To' in message:
                message.add_header('X-Resent-To', message['Resent-To'])
                message.replace_header('Resent-To', recipient)

            else:
                message.add_header('Resent-To', recipient)

            message.add_header('X-Phantom-Remailer', 'Yes')

            self.message = message
            logging.info('Forward %s -> %s alias: %s', message['From'], recipient, self.to_addr)
            return True

        else:
            logging.error('No To address in message')
            return False

    def anonymize_message(self, message: email.message.EmailMessage):
        self.message = email.message.EmailMessage(policy=policy.default)

        # This is a debugging feature to save the as-parsed input so
        # problems can be worked out later.  Just for paranoia I added
        # a header to indicate the message was logged.
        if self.log_messages == True:
            with open('/tmp/message_log', 'a') as f:
                f.write('From {} {}\r\n'.format(self.to_addr,time.asctime(time.gmtime())))
                f.write(message.as_string())
                f.write('\r\n')
            self.message.add_header('X-Message-Logged', 'Yes')

        header_list = ('MIME-Version', 'Subject', 'Content-Language')

        headers=dict()
        for header in header_list:
            if header in message:
                self.message.add_header(header, message.get(header))

        self.message.add_header("From", self.to_addr)
        self.message.add_header("To", self.from_addr)
        msg_date = email.utils.formatdate(usegmt=True)

        self.message.add_header("Date", msg_date)

        if message.is_multipart():
            part = message.get_body(preferencelist=('plain'))
            content = part.get_content()

        else:
            content = message.get_content()

        self.message.set_content(self.strip_signature(content), subtype='plain', cte='quoted-printable')
        logging.info('Anonymize %s as %s -> %s', message['From'], remailer.to_addr, remailer.from_addr)

    def get_smtp_host(self, smtp_host: str = None):
        return smtp_host if smtp_host is not None else self.config['smtp_host']

    def send_message(self, smtp_host: str = None, to: str = None, sender: str = None):
        if debug == False:
            try:
                with SMTP(self.get_smtp_host(smtp_host)) as smtp:
                    smtp.send_message(self.message, from_addr=sender, to_addrs=to)
                    return True

            except Exception as e:
                self.return_code = self.EX_TEMPFAIL
                self.last_exception = e
                logging.critical('Error sending message')
                logging.critical(e)
                return False

        else:
            print('From {}'.format(self.sender))
            print(self.message)
            return True

    def process_message(self, file):
        try:
            message = email.message_from_file(file, policy=policy.default)

            anonymized = self.detect_anonymized(message) 
            if  anonymized == True:
                self.anonymize_message(message)

            elif anonymized == False:
                self.recipient = self.lookup_forward()

                if self.recipient == False:
                    print('No recipient found')
                    self.return_code = self.EX_TEMPFAIL
                    return False

                self.sender = remailer.to_addr

                ret = self.forward_message(message, self.recipient)
                if ret != True:
                    print('No To in message')
                    self.return_code = self.EX_NOUSER
                    return False
            else:
                return False

        except Exception as e:
            exc_text = traceback.format_exc()
            logging.critical('Exception caught in %s:\n%s',__name__, exc_text)
            print(exc_text)
            self.return_code = self.EX_TEMPFAIL
            return False

        return True

    def get_message(self):
        return self.message

    def clear(self):
        self.message.clear()

    def remail(self, file):
        
        ret = self.process_message(file)

        if ret != True:
            return False

        ret = remailer.send_message(sender=self.sender, to=self.recipient)

        if ret != True:
            print(remailer.last_exception)
            return False

        return True


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class TestHarness(unittest.TestCase):
    unittestdir = "test/"
    remailer = None
    testcases = list()

    def setUp(self):
        if self.unittestdir[-1] != '/':
            self.unittestdir = self.unittestdir + '/'

        testcases=next(os.walk(self.unittestdir), (None, None, []))[2]

        for testcase in testcases:
            filename_ext = testcase.split('.')

            if len(filename_ext) == 2 and filename_ext[1] == 'test':
                self.testcases.append(testcase)

    def test_hash_signature(self):
        test_addr = 'test@example.com'

        encoded_addr = remailer.encode_addr(test_addr)

        (address, signature) = encoded_addr.split('.')

        address = remailer.decode_addr(address)
        signature = base64.b64decode(signature)

        compare = remailer.validate_signature(address, signature)

        if compare:
            print(bcolors.OKGREEN,'✔',bcolors.ENDC,'test_hash_signature passed')
        else:
            print(bcolors.FAIL,'✘',bcolors.ENDC,'test_hash_signature failed')

        self.assertTrue(compare)

    def test_message_samples(self):
        print()

        for testcase in self.testcases:

            testcase_path = self.unittestdir + testcase
            result = self.unittestdir + testcase.split('.')[0] + '.result'

            with open(testcase_path, 'r') as message:
                ret = self.remailer.process_message(message)

            #Some test cases don't have a result because they are intended to fail
            #We take the intended result of the test case from its name
            if not exists(result) and 'False' in testcase:
                if ret == False:
                    print(bcolors.OKGREEN,'✔',bcolors.ENDC,testcase_path,'passed')
                else:
                    print(bcolors.FAIL,'✘',bcolors.ENDC,testcase_path,'failed')

                self.assertFalse(ret)
                continue

            else:
                if ret != True:
                    print('ret',ret)
                    print(self.remailer.last_exception)
                    print(self.remailer.return_code)

                self.assertTrue(ret)
            
            with open(result, 'r') as f:
                test_result = f.read()

            message_under_test = self.remailer.get_message() 
            del message_under_test['Date']

            #print tacks on an extra \n, we need to emulate
            message_text = str(message_under_test) + '\n'

            #    print(prev_line.encode('utf-8').hex())
            if message_text != test_result:
                print(bcolors.FAIL,'✘',bcolors.ENDC,testcase_path,'failed')
                #print('message_text',message_text)
                #print('result',result)
                #print('test_result',test_result)
                #print('message_text encode',message_text.encode('utf-8').hex())
                #print('test_result encode',test_result.encode('utf-8').hex())
            else:
                print(bcolors.OKGREEN,'✔',bcolors.ENDC,testcase_path,'passed')
            
            self.assertEqual(message_text, test_result)

            self.remailer.clear()


if __name__ == "__main__":
    # execute only if run as a script
    parser = argparse.ArgumentParser(
        description='Masquerading remailer',
        formatter_class=argparse.RawTextHelpFormatter,
        )
    parser.add_argument('-c', '--config', required=True, dest='config', help='path to the YAML configuration file')
    parser.add_argument('--test', dest='test', action='store_true', help='do not forward, just print to stdout')
    parser.add_argument('--unittest', dest='unittest', action='store_true', help='run unit tests')
    parser.add_argument('--unittestdir', dest='unittestdir', help='directory where unit tests are stored')
    parser.add_argument('--makedb', dest='makedb', action='store_true', 
    help='''Create address alias database by executing
remailer.py --config /path/to/config.yml --makedb < address_list

The address_list file contains addresses formatted like this:
incoming_address@domain.com: forwarding_address@domain.com''')
    args = parser.parse_args()

    debug=False
    if args.test:
        debug=True

    remailer = Remailer()

    ret = remailer.load_config(args.config)

    if ret != True:
        print(remailer.last_exception)
        sys.exit(remailer.return_code)

    if 'logging' in remailer.config and remailer.config['logging'] == True:
        ret = remailer.init_log()

        if ret != True:
            print(remailer.last_exception)
            sys.exit(remailer.return_code)

    if args.makedb:
        ret = remailer.makedb()

        if ret != True:
            print(remailer.last_exception)
            sys.exit(remailer.return_code)

    elif args.unittest and 'unittestdir' in args:
        TestHarness.unittestdir = args.unittestdir
        TestHarness.remailer = remailer

        unittest.main(argv=[__name__])

    else:
        ret = remailer.remail(sys.stdin)

        if ret != True:
            print(ret,remailer.last_exception)
            sys.exit(remailer.return_code)

