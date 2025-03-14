#!/bin/bash

# check if directories exist and if bouncy castle files are present
BCPROV_PATH=$(find / -type f -name "bcprov*.jar" 2>/dev/null | head -n 1)
BCPKIX_PATH=$(find / -type f -name "bcpkix*.jar" 2>/dev/null | head -n 1)

if [[ -z "$BCPROV_PATH" ]]; then
    echo "error: bouncy castle (prov) is not installed." >&2
    exit 1
fi

if [[ -z "$BCPKIX_PATH" ]]; then
    echo "error: bouncy castle (pkix) is not installed." >&2
    exit 1
fi

TEMP_DIR="$(dirname "$0")/tmp"

if [ ! -d "$TEMP_DIR" ]; then
    mkdir -p "$TEMP_DIR"
fi

TEMP_FILE="$TEMP_DIR/Main.java"

# ensure a certificate file is provided
if [ "$#" -lt 1 ]; then
    echo "usage: $0 <certificate>" >&2
    exit 1
fi

CERT_FILE=$(realpath "$1")

# ensure the provided certificate is in PEM format
if ! grep -q "BEGIN CERTIFICATE" "$CERT_FILE" || ! grep -q "END CERTIFICATE" "$CERT_FILE"; then
    echo "error: the provided file is not a certificate in PEM format." >&2
    exit 1
fi

# count the number of certificates in the file
CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$CERT_FILE")

if [ "$CERT_COUNT" -eq 1 ]; then
    echo "import java.io.FileInputStream;
    import java.security.Security;
    import java.security.cert.X509Certificate;
    import java.security.cert.CertificateFactory;

    import org.bouncycastle.jce.provider.BouncyCastleProvider;

    public class Main {
        public static void main(String[] args) throws Exception {

            Security.addProvider(new BouncyCastleProvider());

            FileInputStream fis = new FileInputStream(\"$CERT_FILE\");

            CertificateFactory certificateFactory = CertificateFactory.getInstance(\"X.509\", \"BC\");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fis);

            certificate.getPublicKey(); // infinite loop
        }
    }" > $TEMP_FILE

    # run single certificate parsing
    java --class-path=$BCPROV_PATH $TEMP_FILE
else    
    echo "import java.io.*;
    import java.security.Security;
    import java.security.cert.*;
    import java.util.*;
    import org.bouncycastle.jce.provider.BouncyCastleProvider;
    import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;

    public class Main {
        public static void main(String[] args) throws Exception {
            Security.addProvider(new BouncyCastleProvider());

            CertificateFactory cf = CertificateFactory.getInstance(\"X.509\", \"BC\");
            List<X509Certificate> certChain = new ArrayList<>();

            try (FileInputStream fis = new FileInputStream(\"$CERT_FILE\")) {
                Collection<? extends Certificate> certs = cf.generateCertificates(fis);
                for (Certificate cert : certs) {
                    certChain.add((X509Certificate) cert);
                }
            }

            X509Certificate root = certChain.get(certChain.size() - 1);

            CertPath cp = cf.generateCertPath(certChain);
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            trustAnchors.add(new TrustAnchor(root, null));
            PKIXParameters params = new PKIXParameters(trustAnchors);

            PKIXCertPathReviewer certPathReviewer = new PKIXCertPathReviewer();
            certPathReviewer.init(cp, params);

            certPathReviewer.isValidCertPath();
        }
    }" > $TEMP_FILE

    # verify the certificate chain
    java --class-path=$BCPROV_PATH:$BCPKIX_PATH $TEMP_FILE
fi