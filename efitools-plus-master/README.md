# efitools-plus
Modified efitools for handling Cisco efi variables creating AVs.


# Usage
efi-updatevar --help
efi-updatevar [-a] [-e] [-s <file>] [-engine <engine>] [-w | -d <list>[-<entry>] -v <variable-file>] [-k <key>] [-g <guid>] [-b <file>|-f <file>|-c file] [-n <var>|<var>] [-o <file>]
Manipulate the UEFI key database via the efivarfs filesystem

        -a      append a value to the variable instead of replacing it
        -engine <engine>        openssl engine
        -v <file>       EFI variable file binary dump path.
        -n <var>        EFI Variable name
        -s <file>       Signer certificate file
        -w              Convert the whole variable file into an AV file
        -o <file>       Output AV to this file.
        -e      use EFI Signature List instead of signed update (only works in Setup Mode
        -b <binfile>    Add hash of <binfile> to the signature list
        -f <file>       Add or Replace the key file (.esl or .auth) to the <var>
        -c <file>       Add or Replace the x509 certificate to the <var> (with <guid> if provided)
        -g <guid>       Optional <guid> for the X509 Certificate
        -k <key>        Secret key file for authorising User Mode updates
        -d <list>[-<entry>]     Delete the signature list <list> (or just a single <entry> within the list)
        -t <timestamp>   Use <timestamp> as the timestamp of the timed variable update
                         If not present, then the timestamp will be taken from system
                         time.  Note you must use this option when doing detached
                         signing otherwise the signature will be incorrect because
                         of timestamp mismatches.

# Newly added options

       -engine <engine>        openssl engine
        -v <file>       EFI variable file binary dump path.
        -n <var>        EFI Variable name
        -s <file>       Signer certificate file
        -w              Convert the whole variable file into an AV file
         -o <file>       Output AV to this file.
