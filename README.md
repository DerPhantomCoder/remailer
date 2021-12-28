# Phantom Remailer

This is a masquerading (ne pseudonymous) remailer script that is designed to work with sendmail.

## Usage
To use this you want to either put the remailer.py in your .forward or create an aliase in /etc/aliases.

The pipe command looks like this:

`|/usr/local/bin/remailer.py --config /etc/mail/remailer.yml`

## Config
The remailer uses a YAML config with the following configuration settings:

- map: The DBM file containing the map of the incoming and forwarding email addresses
- smtp_host: The SMTP host to use as a relay for the remailer

## Address alias database
The remailer has another option `--makedb` which creates the DBM aliases file.

To create the aliases, create an input text file in the following format:

```
foo@example.com: bar@example.com
```

The `foo@example.com` is your incoming address to masquerade as, `bar@example.com` is your private email address to forward incoming messages to.

To create the aliases DBM, simply execute this command:

`remailer.py --config /path/to/your/config.yml --makedb < address_list`

## Errors
The remailer implements the Sendmail standard return codes used by mail delivery agents.  These are found in `/usr/includ/sysexits.h` but have no Python equivalent.

I included the appropriate defines taken from the aforementioned header file.  If you extend functionality then be mindful of the exit codes and choose an appropriate one.

When sendmail encounters an error while delivering to an agent, it will send an error report back to the sender that looks like this:

```
   ----- The following addresses had permanent fatal errors -----
"|python3 /usr/local/bin/remailer.py --config /etc/mail/config.yml
    (reason: 1)
    (expanded from: <foo@example.com>)
```

It is important to properly code the return result to ensure the error messages are properly handled.
