# Phantom Remailer

This is a masquerading (ne pseudonymous) remailer script that is designed to
work with sendmail.  It was modeled after the behavior of the Craigslist
remailer, so it works on a _least data_ approach and does not attempt to be
a full featured multipart sanitizer.  This is a _least effort_ approach to
email sanitization and therefore some features may be lacking and some emails
might be broken when remailed.

For incoming (forwarded) emails, it makes as few changes as possible to the message
so that formatting and MIME parts are respected.

Care has been taken to try and scrub the anonymized message
by only allowing a fixed list of headers to be copied from the source message.

The date is recreated on the server running the remailer using GMT as the TZ, and
the body of the message is text/plain.  If a multipart message is sent to the
remailer to be anonymized, the "best guess" (Python's term) of what the plain
message body is is used in the reply.  The signature block is stripped and any
PGP signatures are stripped.

The body is formatted as quoted-printable, eschewing UTF-8 and MIME encoding, this
makes it easy to verify the validity of the message and reduces the potential
for abuse and encoding attacks.

Since the incoming email is parsed into memory, there is a significant limitation
around the size of emails that can be properly parsed and mangled.

## Usage
To use this you want to either put the remailer.py in your .forward or create an
alias in /etc/aliases.

The pipe command looks like this:

`|/usr/local/bin/remailer.py --config /etc/mail/remailer.yml`

## smrsh

Sendmail uses a wrapper called `smrsh` to deliver mail to programs.

smrsh uses an explicit permissions model to allow programs to be executed, therefore
you must create symlinks to `python3` and the `remailer.py` script in the
`/etc/smrsh` directory.

eg:

```
lrwxrwxrwx. 1 root root 16 Dec 22 15:28 python3 -> /usr/bin/python3
lrwxrwxrwx. 1 root root 26 Dec 22 15:28 remailer.py -> /usr/local/bin/remailer.py
```

It is good practice to also relabel those symlinks after you create them:

`restorecon -Frv /etc/smrsh`

## Config
The remailer uses a YAML config with the following configuration settings:

- map: The DBM file containing the map of the incoming and forwarding email
addresses
- smtp_host: The SMTP host to use as a relay for the remailer
- log: Path to log if logging is enabled
- logging: A boolean on/off/True/False/Yes/No to enable or disable logging
- log_level: The log level to write to the log, 1 of DEBUG, INFO, WARNING, ERROR, CRITICAL
- log_messages: A boolean to enable logging of messages to be anonymized.  Used for diagnosing bugs.  This adds a header to the outgoing message to inform that the message was logged.

## Address alias database
The remailer has another option `--makedb` which creates the DBM aliases file.

To create the aliases, create an input text file in the following format:

```
foo@example.com: bar@example.com
```

The `foo@example.com` is your incoming address to masquerade as,
`bar@example.com` is your private email address to forward incoming messages to.

To have a catchall address simply add an entry to the address aliases database
with the key `catchall`, any messages directed to the remailer that do not have
a matching lookup address will be sent to the catchall address:

```
catchall: someone@example.com
```

The return address of anonymized messages is encoded in the `Reply-To` when the
original message is forwarded, this means a catchall address will masquerade
as whatever the `To` address was in the original email.  The address database
is not used for lookups for masquerading, only forwarding.

To create the address aliases DBM, simply execute this command:

`remailer.py --config /path/to/your/config.yml --makedb < address_list`

## Errors
The remailer implements the Sendmail standard return codes used by mail delivery
agents.  These are found in `/usr/include/sysexits.h` but have no Python
equivalent.

I included the appropriate defines taken from the aforementioned header file.
If you extend functionality then be mindful of the exit codes and choose an
appropriate one.

When sendmail encounters an error while delivering to an agent, it will send an
error report back to the sender that looks like this:

```
----- The following addresses had permanent fatal errors -----
"|python3 /usr/local/bin/remailer.py --config /etc/mail/config.yml (reason: 1)
(expanded from: <foo@example.com>)
```

It is important to properly code the return result to ensure the error messages
are properly handled.

The EX_TEMPFAIL return code will cause sendmail to hold the message in deferred
state so it can be reprocessed, this may be the desired default in many cases.

## SELinux
When using SELinux there are a few things to consider:
- Ensure that your configuration and aliases database are readable by user `mail`
- Use `restorecon -Frv` on the directory where your config/alias db resides to ensure they are labeled properly
- Run `setsebool -P domain_can_mmap_files 1` to allow the DBM library to `mmap(2)` the aliases db