#!/bin/python3

import email
from email.policy import default
import smtplib
import sys
import re
import base64

if __name__ == "__main__":

  message = email.message_from_file(sys.stdin,policy=default)

  anonymize = False

  if 'To' in message:
    (name,addr) = email.utils.parseaddr(message['To'])

    result = re.match(r'(?P<box>[^+]+)\+(?P<extra>[^@]+)@(?P<domain>.+)', addr)

    if result:
      encoded_from = result.group('extra').split('.')

      if len(encoded_from) == 2:
        (trigger,encoded_addr) = encoded_from

        if trigger == 'anonymize':
          from_addr = base64.b64decode(encoded_addr)
          anonymize = True

  # handle replies that need remailing to user
  if anonymize == True:
    new_message = email.message.EmailMessage()

    header_list = ('MIME-Version','Subject','Content-Language','Content-Type')
    header_blacklist = ('Received','Message-Id','Date','From','To','Reply-To','User-Agent','Return-Path','Delivered-To')

    """    headers=dict()
        for header in header_list:
          if header in message:
            headers[header]=message.get(header)
    """
    
    for header in header_blacklist:
      del message[header]

    """
        for header in headers:
          message.add_header(header, headers[header])
    """
    
    message.add_header("From", from_addr.decode())
    msg_date = email.utils.formatdate(usegmt=True)

    message.add_header("Date", msg_date)

  else:

    if 'To' in message:
      (name, addr) = email.utils.parseaddr(message['To'])
      (to,domain) = addr.split('@')

      if to is not None and domain is not None:
        if 'From' in message:
          (name, addr) = email.utils.parseaddr(message['From'])
          encoded_from = base64.b64encode(addr.encode())
          message.add_header("Reply-To", to + '+anonymize.' + encoded_from.decode() + '@' + domain)


    message.add_header("X-Phantom-Remailer","yes")

  print(message)