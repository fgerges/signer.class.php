<?php

namespace eth_sign;

class Signer {
    private $algo;
    private $keyDir;

    public function __construct($keydir = 'keys', $algo = OPENSSL_ALGO_SHA256) {
        $this->algo = $algo;
        $this->keyDir = $keydir;
    }

    private function getPrivateKey($hash) {
        return openssl_get_privatekey('file://' . $this->keyDir . "/$hash.private.pem", null);
    }

    public function getPublicKey($hash) {
        return openssl_get_publickey('file://' . $this->keyDir . "/$hash.public.pem");
    }

    public function sign($message, &$signature, $hash) {
        $ret = true;
        $signature = null;
        $privateKey = $this->getPrivateKey($hash);
        if (openssl_sign($message, $signature, $privateKey, $this->algo)) {
            $signature = base64_encode($signature); // data en base64
        } else {
            $ret = false;
        }
        openssl_free_key($privateKey);
        return $ret;
    }

    public function verify($message, $hash) {
        $publicKey =  $this->getPublicKey($hash);
        $ret = openssl_verify($message, base64_decode($message), $publicKey, $this->algo);
        openssl_free_key($publicKey);
        return $ret;
    }

    public function getLastError() {
        return openssl_error_string();
    }

    public function generateKeys($email) {
        $hash = hash('sha256', $email);
        $privateKey = $this->keyDir . "/$hash.private.pem";
        $publicKey = $this->keyDir . "/$hash.public.pem";
        exec('openssl ecparam -name secp256k1 -genkey -out ' . $privateKey);        // ECDSA
        exec('openssl ec -in ' . $privateKey . ' -pubout -out ' . $publicKey);
        return $hash;
    }
}
