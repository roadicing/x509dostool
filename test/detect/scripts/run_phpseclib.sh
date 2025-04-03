#!/bin/bash

# set phpseclib autoload path
PHP_AUTOLOAD_PATH=$(find / -type f -path "*/phpseclib-*/vendor/autoload.php" 2>/dev/null | head -n 1)

if [[ -z "$PHP_AUTOLOAD_PATH" ]]; then
    echo "error: phpseclib is not installed." >&2
    exit 1
fi

# ensure a certificate file is provided
if [ "$#" -lt 1 ]; then
    echo "usage: $0 <certificate>" >&2
    exit 1
fi

CERT_FILE="$1"

# ensure the provided certificate is in PEM format
if ! grep -q "BEGIN CERTIFICATE" "$CERT_FILE" || ! grep -q "END CERTIFICATE" "$CERT_FILE"; then
    echo "error: the provided file is not a certificate in PEM format." >&2
    exit 1
fi

# count the number of certificates in the file
CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$CERT_FILE")

if [ "$CERT_COUNT" -eq 1 ]; then
    # run single certificate parsing
    php -r "
    require '$PHP_AUTOLOAD_PATH';
    use phpseclib3\File\X509;

    \$certContent = file_get_contents('$CERT_FILE');
    \$x509 = new X509();
    \$x509->loadX509(\$certContent);
    \$x509->getPublicKey();
    "
else
    # run certificate chain verification
    php -r "
    require '$PHP_AUTOLOAD_PATH';
    use phpseclib3\File\X509;

    \$certContent = file_get_contents('$CERT_FILE');
    \$certs = explode('-----END CERTIFICATE-----', \$certContent);
    \$x509 = new X509();

    \$first = true;
    foreach (\$certs as \$certData) {
        \$certData = trim(\$certData);
        if (empty(\$certData)) continue;
        \$certData .= '-----END CERTIFICATE-----';
        if (\$first) {
            \$x509->loadX509(\$certData);
            \$first = false;
        } else {
            \$x509->loadCA(\$certData);
        }
    }

    \$valid = \$x509->validateSignature();
    echo \$x509->validateSignature() ? 'valid' : 'invalid';
    "
fi