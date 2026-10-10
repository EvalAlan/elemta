<?php
// Loaded by the roundcube/roundcubemail image from /var/roundcube/config/.
//
// Elemta refuses AUTH PLAIN/LOGIN in the clear from anything but loopback, so
// Roundcube submits over STARTTLS (ROUNDCUBEMAIL_SMTP_SERVER=tls://elemta).
// The dev stack's certificate is self-signed, so peer verification is off
// here. A production webmail must verify the server's certificate.
$config['smtp_conn_options'] = [
    'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
];
