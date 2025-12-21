<?php
declare(strict_types=1);

use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AttestedCredentialData;
use Cose\Algorithm\Manager as AlgorithmManager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Symfony\Component\Uid\Uuid;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Create PublicKeyCredentialCreationOptions for registration
 */
function create_webauthn_registration_options(
    string $rpId,
    string $rpName,
    string $userId,
    string $userName,
    string $userDisplayName,
    string $challenge
): PublicKeyCredentialCreationOptions {
    $rpEntity = PublicKeyCredentialRpEntity::create($rpName, $rpId);
    $userEntity = PublicKeyCredentialUserEntity::create($userName, $userId, $userDisplayName);
    
    $pubKeyCredParams = [
        PublicKeyCredentialParameters::create('public-key', -7),  // ES256
        PublicKeyCredentialParameters::create('public-key', -257), // RS256
    ];
    
    $authenticatorSelection = AuthenticatorSelectionCriteria::create()
        ->setResidentKey(AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED)
        ->setUserVerification(AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED);
    
    return PublicKeyCredentialCreationOptions::create(
        $rpEntity,
        $userEntity,
        $challenge,
        $pubKeyCredParams,
        $authenticatorSelection,
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        [],
        60000
    );
}

/**
 * Create PublicKeyCredentialRequestOptions for authentication
 */
function create_webauthn_authentication_options(
    string $rpId,
    string $challenge
): PublicKeyCredentialRequestOptions {
    return PublicKeyCredentialRequestOptions::create($challenge)
        ->setRpId($rpId)
        ->setTimeout(60000)
        ->setUserVerification(PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED);
}

/**
 * Verify attestation during registration
 */
function verify_webauthn_attestation(
    PublicKeyCredentialCreationOptions $options,
    string $credentialIdBase64Url,
    string $attestationObjectBase64Url,
    string $clientDataJSONBase64Url,
    string $rpId
): PublicKeyCredentialSource {
    // Decode inputs
    $credentialId = b64url_decode($credentialIdBase64Url);
    $attestationObject = b64url_decode($attestationObjectBase64Url);
    $clientDataJSON = b64url_decode($clientDataJSONBase64Url);
    
    if ($credentialId === '' || $attestationObject === '' || $clientDataJSON === '') {
        throw new Exception('Invalid credential data');
    }
    
    // Parse client data
    $clientData = json_decode($clientDataJSON, true);
    if (!is_array($clientData)) {
        throw new Exception('Invalid client data JSON');
    }
    
    // Verify type
    if (($clientData['type'] ?? '') !== 'webauthn.create') {
        throw new Exception('Invalid client data type');
    }
    
    // Verify challenge
    $receivedChallenge = $clientData['challenge'] ?? '';
    $expectedChallenge = b64url_encode($options->challenge);
    if (!hash_equals($expectedChallenge, $receivedChallenge)) {
        throw new Exception('Challenge mismatch');
    }
    
    // Verify origin
    $origin = $clientData['origin'] ?? '';
    $expectedOrigin = 'https://' . $rpId;
    // Allow http for localhost during development
    if (in_array($rpId, ['localhost', '127.0.0.1'], true)) {
        $expectedOrigin = 'http://' . $rpId;
        // Also check common dev ports
        if (!str_starts_with($origin, $expectedOrigin)) {
            $expectedOrigin = 'http://' . $rpId . ':';
        }
    }
    
    if (!str_starts_with($origin, $expectedOrigin)) {
        throw new Exception('Origin mismatch: expected ' . $expectedOrigin . ', got ' . $origin);
    }
    
    // Parse attestation object (CBOR)
    try {
        $attestationDecoded = \CBOR\CBOREncoder::decode($attestationObject);
    } catch (Throwable $e) {
        throw new Exception('Failed to decode attestation object: ' . $e->getMessage());
    }
    
    if (!is_array($attestationDecoded)) {
        throw new Exception('Invalid attestation object structure');
    }
    
    // Extract authData
    $authData = $attestationDecoded['authData'] ?? null;
    if (!is_string($authData) || strlen($authData) < 37) {
        throw new Exception('Invalid authenticator data');
    }
    
    // Parse authenticator data
    $rpIdHash = substr($authData, 0, 32);
    $expectedRpIdHash = hash('sha256', $rpId, true);
    if (!hash_equals($expectedRpIdHash, $rpIdHash)) {
        throw new Exception('RP ID hash mismatch');
    }
    
    $flags = ord($authData[32]);
    $userPresent = ($flags & 0x01) !== 0;
    $userVerified = ($flags & 0x04) !== 0;
    $hasAttestedCredData = ($flags & 0x40) !== 0;
    
    if (!$userPresent) {
        throw new Exception('User not present');
    }
    
    if (!$hasAttestedCredData) {
        throw new Exception('No attested credential data');
    }
    
    // Extract counter
    $counter = unpack('N', substr($authData, 33, 4))[1];
    
    // Parse attested credential data (starts at byte 37)
    $offset = 37;
    $aaguid = substr($authData, $offset, 16);
    $offset += 16;
    
    $credIdLen = unpack('n', substr($authData, $offset, 2))[1];
    $offset += 2;
    
    $parsedCredId = substr($authData, $offset, $credIdLen);
    $offset += $credIdLen;
    
    if (!hash_equals($credentialId, $parsedCredId)) {
        throw new Exception('Credential ID mismatch');
    }
    
    // Extract public key (CBOR encoded COSE key)
    $publicKeyCbor = substr($authData, $offset);
    try {
        $publicKeyData = \CBOR\CBOREncoder::decode($publicKeyCbor);
    } catch (Throwable $e) {
        throw new Exception('Failed to decode public key: ' . $e->getMessage());
    }
    
    if (!is_array($publicKeyData)) {
        throw new Exception('Invalid public key structure');
    }
    
    // Verify algorithm (COSE key type)
    $kty = $publicKeyData[1] ?? null; // key type
    $alg = $publicKeyData[3] ?? null; // algorithm
    
    // Support ES256 (-7) and RS256 (-257)
    if (!in_array($alg, [-7, -257], true)) {
        throw new Exception('Unsupported algorithm: ' . var_export($alg, true));
    }
    
    // Create PublicKeyCredentialSource
    return PublicKeyCredentialSource::create(
        $credentialId,
        'public-key',
        [],
        'none',
        EmptyTrustPath::create(),
        Uuid::fromBinary($aaguid),
        $publicKeyCbor,
        $options->user->id,
        $counter
    );
}

/**
 * Verify assertion during authentication
 */
function verify_webauthn_assertion(
    PublicKeyCredentialRequestOptions $options,
    string $credentialIdBase64Url,
    string $authenticatorDataBase64Url,
    string $clientDataJSONBase64Url,
    string $signatureBase64Url,
    PublicKeyCredentialSource $credentialSource,
    string $rpId
): PublicKeyCredentialSource {
    // Decode inputs
    $credentialId = b64url_decode($credentialIdBase64Url);
    $authenticatorData = b64url_decode($authenticatorDataBase64Url);
    $clientDataJSON = b64url_decode($clientDataJSONBase64Url);
    $signature = b64url_decode($signatureBase64Url);
    
    if ($credentialId === '' || $authenticatorData === '' || $clientDataJSON === '' || $signature === '') {
        throw new Exception('Invalid assertion data');
    }
    
    // Verify credential ID matches
    if (!hash_equals($credentialSource->publicKeyCredentialId, $credentialId)) {
        throw new Exception('Credential ID mismatch');
    }
    
    // Parse client data
    $clientData = json_decode($clientDataJSON, true);
    if (!is_array($clientData)) {
        throw new Exception('Invalid client data JSON');
    }
    
    // Verify type
    if (($clientData['type'] ?? '') !== 'webauthn.get') {
        throw new Exception('Invalid client data type');
    }
    
    // Verify challenge
    $receivedChallenge = $clientData['challenge'] ?? '';
    $expectedChallenge = b64url_encode($options->challenge);
    if (!hash_equals($expectedChallenge, $receivedChallenge)) {
        throw new Exception('Challenge mismatch');
    }
    
    // Verify origin
    $origin = $clientData['origin'] ?? '';
    $expectedOrigin = 'https://' . $rpId;
    // Allow http for localhost during development
    if (in_array($rpId, ['localhost', '127.0.0.1'], true)) {
        $expectedOrigin = 'http://' . $rpId;
        // Also check common dev ports
        if (!str_starts_with($origin, $expectedOrigin)) {
            $expectedOrigin = 'http://' . $rpId . ':';
        }
    }
    
    if (!str_starts_with($origin, $expectedOrigin)) {
        throw new Exception('Origin mismatch');
    }
    
    // Parse authenticator data
    if (strlen($authenticatorData) < 37) {
        throw new Exception('Invalid authenticator data length');
    }
    
    $rpIdHash = substr($authenticatorData, 0, 32);
    $expectedRpIdHash = hash('sha256', $rpId, true);
    if (!hash_equals($expectedRpIdHash, $rpIdHash)) {
        throw new Exception('RP ID hash mismatch');
    }
    
    $flags = ord($authenticatorData[32]);
    $userPresent = ($flags & 0x01) !== 0;
    $userVerified = ($flags & 0x04) !== 0;
    
    if (!$userPresent) {
        throw new Exception('User not present');
    }
    
    // Extract counter
    $counter = unpack('N', substr($authenticatorData, 33, 4))[1];
    
    // Verify counter (replay protection)
    if ($counter > 0 && $counter <= $credentialSource->counter) {
        throw new Exception('Counter did not increase (possible replay attack)');
    }
    
    // Verify signature
    $clientDataHash = hash('sha256', $clientDataJSON, true);
    $signedData = $authenticatorData . $clientDataHash;
    
    // Decode the public key from CBOR
    try {
        $publicKeyData = \CBOR\CBOREncoder::decode($credentialSource->credentialPublicKey);
    } catch (Throwable $e) {
        throw new Exception('Failed to decode stored public key: ' . $e->getMessage());
    }
    
    if (!is_array($publicKeyData)) {
        throw new Exception('Invalid stored public key structure');
    }
    
    $alg = $publicKeyData[3] ?? null;
    
    // Verify signature based on algorithm
    if ($alg === -7) {
        // ES256 (ECDSA with SHA-256)
        if (!verify_es256_signature($publicKeyData, $signedData, $signature)) {
            throw new Exception('Signature verification failed');
        }
    } elseif ($alg === -257) {
        // RS256 (RSA with SHA-256)
        if (!verify_rs256_signature($publicKeyData, $signedData, $signature)) {
            throw new Exception('Signature verification failed');
        }
    } else {
        throw new Exception('Unsupported algorithm for verification');
    }
    
    // Update counter
    $credentialSource->counter = $counter;
    
    return $credentialSource;
}

/**
 * Verify ES256 signature
 */
function verify_es256_signature(array $publicKeyData, string $signedData, string $signature): bool {
    // Extract public key coordinates
    $crv = $publicKeyData[-1] ?? null; // curve
    $x = $publicKeyData[-2] ?? null;   // x coordinate
    $y = $publicKeyData[-3] ?? null;   // y coordinate
    
    if ($crv !== 1 || !is_string($x) || !is_string($y)) {
        throw new Exception('Invalid ES256 public key');
    }
    
    // P-256 curve, construct public key in PEM format
    // This is a DER-encoded SubjectPublicKeyInfo structure for an EC public key
    $pubKeyDer = "\x30\x59" . // SEQUENCE, 89 bytes
        "\x30\x13" . // SEQUENCE, 19 bytes (AlgorithmIdentifier)
        "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" . // OID: ecPublicKey
        "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07" . // OID: prime256v1 (P-256)
        "\x03\x42\x00" . // BIT STRING, 66 bytes
        "\x04" . $x . $y; // uncompressed point format
    
    $pem = "-----BEGIN PUBLIC KEY-----\n" . 
           chunk_split(base64_encode($pubKeyDer), 64, "\n") . 
           "-----END PUBLIC KEY-----";
    
    $pubKey = openssl_pkey_get_public($pem);
    if ($pubKey === false) {
        throw new Exception('Failed to parse ES256 public key');
    }
    
    $hash = hash('sha256', $signedData, true);
    
    // ES256 signature is raw r||s format, need to convert to DER for OpenSSL
    if (strlen($signature) !== 64) {
        // Might already be DER encoded, try as-is
        $result = openssl_verify($hash, $signature, $pubKey, OPENSSL_ALGO_SHA256);
    } else {
        // Convert raw signature (r||s) to DER
        $r = substr($signature, 0, 32);
        $s = substr($signature, 32, 32);
        $derSig = encode_der_signature($r, $s);
        $result = openssl_verify($hash, $derSig, $pubKey, OPENSSL_ALGO_SHA256);
    }
    
    return $result === 1;
}

/**
 * Verify RS256 signature
 */
function verify_rs256_signature(array $publicKeyData, string $signedData, string $signature): bool {
    // Extract RSA modulus and exponent
    $n = $publicKeyData[-1] ?? null; // modulus
    $e = $publicKeyData[-2] ?? null; // exponent
    
    if (!is_string($n) || !is_string($e)) {
        throw new Exception('Invalid RS256 public key');
    }
    
    // Construct RSA public key in PEM format
    $nBigInt = gmp_import($n);
    $eBigInt = gmp_import($e);
    
    // Create DER-encoded RSAPublicKey
    $nHex = str_pad(gmp_strval($nBigInt, 16), strlen($n) * 2, '0', STR_PAD_LEFT);
    $eHex = str_pad(gmp_strval($eBigInt, 16), strlen($e) * 2, '0', STR_PAD_LEFT);
    
    $nDer = encode_der_integer(hex2bin($nHex));
    $eDer = encode_der_integer(hex2bin($eHex));
    $rsaPubKeyDer = "\x30" . chr(strlen($nDer . $eDer)) . $nDer . $eDer;
    
    // Wrap in SubjectPublicKeyInfo
    $algId = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00"; // rsaEncryption + NULL
    $spkiDer = "\x30" . chr(strlen($algId . "\x03" . chr(strlen($rsaPubKeyDer) + 1) . "\x00" . $rsaPubKeyDer)) .
               $algId .
               "\x03" . chr(strlen($rsaPubKeyDer) + 1) . "\x00" . $rsaPubKeyDer;
    
    $pem = "-----BEGIN PUBLIC KEY-----\n" . 
           chunk_split(base64_encode($spkiDer), 64, "\n") . 
           "-----END PUBLIC KEY-----";
    
    $pubKey = openssl_pkey_get_public($pem);
    if ($pubKey === false) {
        throw new Exception('Failed to parse RS256 public key');
    }
    
    $hash = hash('sha256', $signedData, true);
    $result = openssl_verify($hash, $signature, $pubKey, OPENSSL_ALGO_SHA256);
    
    return $result === 1;
}

/**
 * Helper to encode DER INTEGER
 */
function encode_der_integer(string $bytes): string {
    // Add leading zero if high bit is set
    if (ord($bytes[0]) & 0x80) {
        $bytes = "\x00" . $bytes;
    }
    return "\x02" . chr(strlen($bytes)) . $bytes;
}

/**
 * Helper to convert raw ECDSA signature to DER
 */
function encode_der_signature(string $r, string $s): string {
    $rDer = encode_der_integer($r);
    $sDer = encode_der_integer($s);
    $seq = $rDer . $sDer;
    return "\x30" . chr(strlen($seq)) . $seq;
}
