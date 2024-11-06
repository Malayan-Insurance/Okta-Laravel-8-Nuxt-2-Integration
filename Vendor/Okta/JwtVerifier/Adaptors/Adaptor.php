<?php

namespace App\Vendor\Okta\JwtVerifier\Adaptors;

use App\Vendor\Okta\JwtVerifier\Jwt;

/**
 * Interface Adaptor
 *
 * This interface defines the required methods that any JWT adaptor class must implement.
 * An adaptor is responsible for handling JWT decoding and key retrieval using a specific
 * JWT library, such as Firebase JWT or other custom libraries. The adaptor also includes
 * methods to check if the necessary JWT package is available in the system.
 */
interface Adaptor
{
    /**
     * Retrieve the public keys from a given JKU (JSON Web Key URL).
     *
     * This method is responsible for fetching the public keys from a specified JKU URL.
     * The JKU URL typically points to a JSON Web Key Set (JWKS) endpoint that contains
     * public keys used to verify the authenticity of JWTs.
     * 
     * @param string $jku The JSON Web Key URL (JWKS) to retrieve the keys from.
     * 
     * @return array An array of public keys from the JWKS.
     */
    public function getKeys(string $jku);

    /**
     * Decode a JWT (JSON Web Token) using the provided public keys.
     *
     * This method takes a JWT string and a set of public keys and decodes the JWT. It 
     * returns a `Jwt` object containing the decoded claims from the token.
     * 
     * @param string $jwt The JWT to decode.
     * @param array $keys An array of public keys used for decoding the JWT.
     * 
     * @return Jwt A `Jwt` object containing the decoded JWT claims.
     */
    public function decode($jwt, $keys): Jwt;

    /**
     * Check if the necessary JWT package is available.
     *
     * This static method checks if the required JWT package or library is available.
     * It is used to determine if the adaptor can be used in the current environment.
     * 
     * @return bool Returns true if the package is available, false otherwise.
     */
    public static function isPackageAvailable();
}
