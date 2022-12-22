
A script to fetch missing intermediate certs for a website.

In TLS, there is a chain of certificates going from the root to the individual certificate signing the connection. A HTTPS web server is supposed to send along all certificates involved (minus the root), but some misconfigured servers only send the final certificate. Web browsers can find the intermediate certificates themselves using a technique called AIA (Authority Information Access). However, many other HTTPS clients do not do this, so you sometimes have websites that you can access in the browser, but cannot access with `wget` for example.

This script looks at the certificate for a host, fetches intermediate certificates, and saves the missing certificates to disk. You can then import them into your certificate store (e.g. /usr/share/ca-certificates), and you will be able to safely connect to the host.

## Usage

```bash
$ python -m venv venv
$ . venv/bin/activate
$ pip install -r requirements.txt
# Replace with host name
$ python fetch.py incomplete-chain.badssl.com
Writing to filename: certs/DigiCert_SHA2_Secure_Server_CA.crt
```

What I do on Ubuntu to trust the certificate is to copy `certs/DigiCert_SHA2_Secure_Server_CA.crt` to `/usr/share/ca-certificates/extra`, then do `sudo dpkg-reconfigure ca-certificates`. It will ask you if it should trust new certificates on updates - choose any option you like. In the next screen, you will be asked which certificates to activate. Add a checkmark to the new one, and you should be done.

## Warning

Use at your own risk. The certificate chain fetched via AIA is validated by the python package `aia`, but we make no other effort at checking if the saved certificate is OK. Other problems like expired certificates are not handled at all.

As it is just a script, the code is not the most efficient. We make two TLS connections to the server, one via the `aia` package, and one via `pyopenssl`, since only the latter allows us to see the full sequence of certificates sent by the server.