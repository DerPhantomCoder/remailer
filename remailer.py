#!/bin/python3

import email
from email import policy
from email.parser import BytesFeedParser
from smtplib import SMTP
import logging
import argparse
import yaml
from dbm import gnu as gdbm
import time
import sys
import re
import base64
import tempfile
import traceback

class Remailer:
    to_addr:str = None
    from_addr:str = None
    return_code:int = None
    last_exception = None
    log_messages:bool = False

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

            logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', filename=filename, level=log_level)

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
                encoded_addrs = result.group('extra').split('.')

                if len(encoded_addrs) == 3:
                    (trigger, encoded_to, encoded_from) = encoded_addrs

                if trigger == self.trigger_string:
                    self.to_addr = base64.b64decode(encoded_to)
                    self.from_addr = base64.b64decode(encoded_from)
                    return True

                else: #no trigger string match
                    return False

            else: #regex not matched
                self.to_addr = addr
                return False

        else: #no To header
            logging.error('No To address in message')
            return False

    def encode_addr(self, address: str):
        (name, addr) = email.utils.parseaddr(address)
        return base64.b64encode(addr.encode()).decode()

    def strip_signature(self, content: str):
        buffer:str = ''
        prev_line:str = None

        for line in content.splitlines(keepends=True):
            if prev_line == '\r\n':
                if line.strip() == '--':
                    break
            else:
                buffer = buffer + line
        
            prev_line = line

        return buffer

    def forward_message(self, message: email.message.EmailMessage, recipient: str):
        if 'To' in message:
            (name, addr) = email.utils.parseaddr(message['To'])
            (to, domain) = addr.split('@')

            if to is not None and domain is not None:
                if 'From' in message:
                    encoded_from = self.encode_addr(message['From'])
                    encoded_to = self.encode_addr(message['To'])

                    message.add_header("Reply-To", to + '+' + self.trigger_string + '.' + encoded_to + '.' + encoded_from + '@' + domain)

            message.add_header('Resent-To', recipient)

            message.add_header('X-Phantom-Remailer', 'Yes')

            self.message = message
            logging.info('Forward %s -> %s alias: %s', message['From'], recipient, sender)
            return True

        else:
            logging.error('No To address in message')
            return False

    def anonymize_message(self, message: email.message.EmailMessage):
        self.message = email.message.EmailMessage(policy=policy.SMTP)

        # This is a debugging feature to save the as-parsed input so
        # problems can be worked out later.  Just for paranoia I added
        # a header to indicate the message was logged.
        if self.log_messages == True:
            with open('/tmp/message_log', 'a') as f:
                message.set_unixfrom('From {} {}'.format(self.to_addr.decode(),time.asctime(time.gmtime())))
                f.write(message.as_string(unixfrom=True))
                f.write('\r\n')
            self.message.add_header('X-Message-Logged', 'Yes')

        header_list = ('MIME-Version', 'Subject', 'Content-Language')

        headers=dict()
        for header in header_list:
            if header in message:
                self.message.add_header(header, message.get(header))

        self.message.add_header("From", self.to_addr.decode())
        self.message.add_header("To", self.from_addr.decode())
        msg_date = email.utils.formatdate(usegmt=True)

        self.message.add_header("Date", msg_date)

        if message.is_multipart():
            part = message.get_body(preferencelist=('plain'))
            content = part.get_content()

        else:
            content = message.get_content()

        self.message.set_content(self.strip_signature(content), subtype='plain', cte='quoted-printable')
        logging.info('Anonymize %s as %s -> %s', message['From'], remailer.to_addr.decode(), remailer.from_addr.decode())

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
            print(self.message)
            return True


if __name__ == "__main__":
    # execute only if run as a script
    parser = argparse.ArgumentParser(
        description='Masquerading remailer',
        formatter_class=argparse.RawTextHelpFormatter,
        )
    parser.add_argument('-c', '--config', required=True, dest='config', help='path to the YAML configuration file')
    parser.add_argument('--test', dest='test', action='store_true', help='do not forward, just print to stdout')
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

    else:
        try:
            message = email.message_from_file(sys.stdin, policy=policy.SMTP)
            recipient = None
            sender = None

            if remailer.detect_anonymized(message):
                remailer.anonymize_message(message)

            else:
                recipient = remailer.lookup_forward()

                if recipient == False:
                    print('No recipient found')
                    sys.exit(remailer.return_code)

                sender = remailer.to_addr

                ret = remailer.forward_message(message, recipient)
                if ret != True:
                    print('No To in message')
                    sys.exit(remailer.EX_NOUSER)

        except Exception as e:
            exc_text = traceback.format_exc()
            logging.critical('Exception caught in %s:\n%s',__name__, exc_text)
            print(e)
            sys.exit(remailer.EX_TEMPFAIL)

        ret = remailer.send_message(sender=sender, to=recipient)

        if ret != True:
            print(remailer.last_exception)
            sys.exit(remailer.return_code)

