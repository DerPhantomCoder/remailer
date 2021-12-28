#!/bin/python3

import email
from email import policy
from email.parser import BytesFeedParser
from smtplib import SMTP
import argparse
import yaml
import dbm
import sys
import re
import base64
import quopri

class Remailer:
    to_addr:str = None
    from_addr:str = None
    return_code:int = None
    last_exception = None

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

    def load_config(self, path: str):
        try:
            if path is not None:
                with open(path, "r") as f:
                    self.config = yaml.load(f, Loader=yaml.SafeLoader)

                return True

            else:
                self.return_code = self.EX_USAGE
                return False

        except PermissionError as e:
            self.return_code = self.EX_NOPERM
            self.last_exception = e
            return False

        except Exception as e:
            self.return_code = self.EX_CONFIG
            self.last_exception = e
            return False

    def lookup_forward(self, address: str = None):
        if address is not None:
            lookup_addr = address
        else:
            lookup_addr = self.to_addr

        try:
            with dbm.open(self.config['map']) as db:
                
                if lookup_addr not in db:
                    if self.catchall_address not in db:
                        self.return_code = self.EX_NOUSER
                        return False
                    else:
                        return db[self.catchall_address].decode()

                else:
                    return db[lookup_addr].decode()

        except PermissionError as e:
            self.return_code = self.EX_NOPERM
            self.last_exception = e
            return False

        except Exception as e:
            self.return_code = self.EX_IOERR
            self.last_exception = e
            return False

    def makedb(self):
        try:
            with dbm.open(self.config['map'],flag='n') as db:
                for line in sys.stdin:
                    (email_in,email_out)=line.split(':')
                    db[email_in.strip()]=email_out.strip()

            return True

        except PermissionError as e:
            self.return_code = self.EX_NOPERM
            self.last_exception = e
            return False
            
        except Exception as e:
            self.return_code = self.EX_IOERR
            self.last_exception = e
            return False

    def detect_anonymized(self, message: email.message.EmailMessage):
        if 'To' in message:
            (name,addr) = email.utils.parseaddr(message['To'])

            result = re.match(r'(?P<box>[^+]+)\+(?P<extra>[^@]+)@(?P<domain>.+)', addr)

            if result:
                encoded_addrs = result.group('extra').split('.')

                if len(encoded_addrs) == 3:
                    (trigger,encoded_to,encoded_from) = encoded_addrs

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
            return False

    def encode_addr(self, address: str):
        (name, addr) = email.utils.parseaddr(address)
        return base64.b64encode(addr.encode()).decode()

    def strip_signature(self, content: str):
        buffer:str = ''
        prev_line:str = ''

        for line in content.splitlines(keepends=True):
            if line == '--\r\n' and prev_line == '\r\n':
                break
            else:
                prev_line = line
                buffer = buffer + line
        
        return buffer

    def forward_message(self, message: email.message.EmailMessage, recipient: str):
        if 'To' in message:
            (name, addr) = email.utils.parseaddr(message['To'])
            (to,domain) = addr.split('@')

            if to is not None and domain is not None:
                if 'From' in message:
                    encoded_from = self.encode_addr(message['From'])
                    encoded_to = self.encode_addr(message['To'])

                    message.add_header("Reply-To", to + '+' + self.trigger_string + '.' + encoded_to + '.' + encoded_from + '@' + domain)

            message.add_header('X-Original-To', msg['To'])
            message.replace_header('To', recipient)

            message.add_header("X-Phantom-Remailer","yes")

            self.message = message
            return True

        else:
            return False

    def anonymize_message(self, message: email.message.EmailMessage):
        self.message = email.message.EmailMessage()

        header_list = ('MIME-Version','Subject','Content-Language')

        headers=dict()
        for header in header_list:
            if header in message:
                self.message.add_header(header,message.get(header))

        self.message.add_header("From", self.to_addr.decode())
        self.message.add_header("To", self.from_addr.decode())
        msg_date = email.utils.formatdate(usegmt=True)

        self.message.add_header("Date", msg_date)

        if message.is_multipart():
            part = message.get_body(preferencelist=('plain'))
            content = part.get_content()

        else:
            content = message.get_content()

        self.message.set_content(self.strip_signature(content),subtype='plain',cte='quoted-printable')

    def get_smtp_host(self, smtp_host: str = None):
        return smtp_host if smtp_host is not None else self.config['smtp_host']

    def send_message(self, smtp_host: str = None):
        if debug == False:
            try:
                with SMTP(self.get_smtp_host(smtp_host)) as smtp:
                    smtp.send_message(self.message)
                    return True

            except Exception as e:
                self.return_code = self.EX_TEMPFAIL
                self.last_exception = e
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

    print(remailer.config)
    if args.makedb:
        ret = remailer.makedb()

        if ret != True:
            print(remailer.last_exception)
            sys.exit(remailer.return_code)

    else:
        try:
            message = email.message_from_file(sys.stdin,policy=policy.default)

            if remailer.detect_anonymized(message):
                remailer.anonymize_message(message)

            else:
                recipient = remailer.lookup_forward()

                if recipient == False:
                    print(remailer.last_exception)
                    sys.exit(remailer.return_code)

                ret = remailer.forward_message(message,recipient)
                if ret != True:
                    print('No To in message')
                    sys.exit(remailer.EX_NOUSER)

        except Exception as e:
            print(e)
            sys.exit(remailer.EX_TEMPFAIL)

        ret = remailer.send_message()
        if ret != True:
            print(remailer.last_exception)
            sys.exit(remailer.return_code)

