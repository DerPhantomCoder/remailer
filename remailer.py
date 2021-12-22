#!/bin/python3

import email
from email import policy
from smtplib import SMTP
import sys
import re
import base64

smtp_host = 'localhost'

if __name__ == "__main__":

  if len(sys.argv) < 2:
    print('email recipient missing')
    exit()
  else:
    relay_to = sys.argv[1]

  debug=False
  if len(sys.argv) > 2:
    debug=True

  message = email.message_from_file(sys.stdin,policy=policy.default)

  anonymize = False

  if 'To' in message:
    (name,addr) = email.utils.parseaddr(message['To'])

    result = re.match(r'(?P<box>[^+]+)\+(?P<extra>[^@]+)@(?P<domain>.+)', addr)

    if result:
      encoded_addrs = result.group('extra').split('.')

      if len(encoded_addrs) == 3:
        (trigger,encoded_to,encoded_from) = encoded_addrs

        if trigger == 'anonymize':
          to_addr = base64.b64decode(encoded_to)
          from_addr = base64.b64decode(encoded_from)
          anonymize = True

  # handle replies that need remailing to user
  if anonymize == True:
    new_message = email.message.EmailMessage()
#    new_message.set_default_type('text/plain')

    header_list = ('MIME-Version','Subject','Content-Language')
    #header_list = ('MIME-Version','Subject','Content-Language','Content-Type')

    headers=dict()
    for header in header_list:
      if header in message:
        new_message.add_header(header,message.get(header))
    
    new_message.add_header("From", to_addr.decode())
    new_message.add_header("To", from_addr.decode())
    msg_date = email.utils.formatdate(usegmt=True)

    new_message.add_header("Date", msg_date)

    if message.is_multipart():
      for part in message.walk():
        if part.get_content_maintype() == 'multipart':
            continue

        if part.get_content_type() == 'text/plain':
          content = part.get_content()
          print(content)

          new_message.set_content(content)
          break
    else:
      content = message.get_content()

      new_message.set_content(content,subtype='plain',cte='quoted-printable')

    if debug == False:
      with SMTP(smtp_host) as smtp:
        smtp.send_message(new_message)
    else:
      print(new_message)
  else:

    if 'To' in message:
      (name, addr) = email.utils.parseaddr(message['To'])
      (to,domain) = addr.split('@')

      if to is not None and domain is not None:
        if 'From' in message:
          (name, addr) = email.utils.parseaddr(message['From'])
          encoded_from = base64.b64encode(addr.encode())
          (name, addr) = email.utils.parseaddr(message['To'])
          encoded_to = base64.b64encode(addr.encode())
          message.add_header("Reply-To", to + '+anonymize.' + encoded_to.decode() + '.' + encoded_from.decode() + '@' + domain)

      message.replace_header('To', relay_to)

    message.add_header("X-Phantom-Remailer","yes")

    if debug == False:
      with SMTP(smtp_host) as smtp:
        smtp.send_message(message)
    else:
      print(message)
