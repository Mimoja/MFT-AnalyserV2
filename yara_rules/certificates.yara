rule CRYPTO_PEM
{
    strings:
    $CERT               = "-----BEGIN CERTIFICATE"
	$CERT_REQ           = "-----BEGIN CERTIFICATE REQ"
	$CERT_NEW           = "-----BEGIN NEW CERTIFICATE"

	$KEY_RSA_PRIV       = "-----BEGIN RSA PRIVATE"
    $KEY_DSA_PRIV       = "-----BEGIN DSA PRIVATE"
    $KEY_EC_PRIV        = "-----BEGIN EC PRIVATE"
	$KEY_PRIV           = "-----BEGIN PRIVATE"
    $KEY_ENC_PRIV       = "-----BEGIN ENCRYPTED PRIVATE"
	$KEY_OPENSSH_PRIV   = "-----BEGIN OPENSSH PRIVATE"
	$KEY_SSH_PRIV       = "-----BEGIN SSH PRIVATE"

	$KEY_SSH_PUB        = "-----BEGIN SSH PUBLIC"
	$KEY_RSA_PUB        = "-----BEGIN RSA PUBLIC"
    $KEY_DSA_PUB        = "-----BEGIN DSA PUBLIC"
    $KEY_EC_PUB         = "-----BEGIN EC PUBLIC"
	$KEY_PUB            = "-----BEGIN PUBLIC"

	$KEY_PGP_PUB        = "-----BEGIN PGP PUBLIC KEY BLOCK"
	$MESSAGE_PGP        = "-----BEGIN PGP MESSAGE"
	$MESSGAE_PGP_SIGNED = "-----BEGIN PGP SIGNED MESSAGE"
	$SIGNATURE_PGP      = "-----BEGIN PGP PGP SIGNATURE"

	$REST               = "-----BEGIN"
	$REST_SHORT         = "---BEGIN"

    condition:
        any of them
}

rule CRYPTO_SSH {
    strings:
	$KEY_PEM_PRIV        = "SSH PRIVATE KEY"
	$KEY_PRIV_DSS        = "ssh-dss "
	$KEY_PRIV_RSA        = "ssh-rsa "
	$KEY_PRIV_ECDSA_P256 = "ecdsa-sha2-nistp256 "
	$KEY_PRIV_ECDSA_P384 = "ecdsa-sha2-nistp384 "
	$KEY_PRIV_ECDSA_P521 = "ecdsa-sha2-nistp521 "

    condition:
	any of them
}

rule CRYPTO_DER {
    strings:
	$KEY_PRIV    = {30 82 ?? ?? 02 01 00}
	$KEY_PUB     = {30 82 ?? ?? 30 0d 06}
	$CERT        = {30 82 ?? ?? 30 82 ??}
	$KEY_RSA_PUB = {30 82 ?? ?? 02 82 01}
	//$UNKNOWN1    = {30 82 01 0E 91 60 34}
	//$UNKNOWN2    = {30 82 01 22 30 0D 06} // Pubkey inside cert
	//$UNKNOWN3    = {30 82 01 87 30 35 ??}
	//$UNKNOWN4    = {30 82 01 8B 8D AF FC}
	//$UNKNOWN5    = {30 82 01 B7 30 1F 06}
	//$UNKNOWN6    = {30 82 01 C9 30 12 06}
	//$UNKNOWN7    = {30 82 02 1C 02 01 01}
	//$UNKNOWN8    = {30 82 04 1? A0 03 02}
	//$UNKNOWN9    = {30 82 0D 07 02 01 01} // PRIV key ?
	//$UNKNOWN10   = {30 82 0D 1A 06 09 2A}
    //$UNKNOWN     = {30 82 0? ?? ?? ?? ??}

    condition:
	any of them
}