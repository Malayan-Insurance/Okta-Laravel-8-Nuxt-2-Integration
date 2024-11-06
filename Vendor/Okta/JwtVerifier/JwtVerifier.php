<?php

namespace App\Vendor\Okta\JwtVerifier;

use App\Vendor\Okta\JwtVerifier\Adaptors\Adaptor;
use App\Vendor\Okta\JwtVerifier\Adaptors\AutoDiscover;
use App\Vendor\Okta\JwtVerifier\Discovery\DiscoveryMethod;
use App\Vendor\Okta\JwtVerifier\Discovery\Oauth;

/**
 * Class JwtVerifier
 *
 * This class is responsible for verifying JSON Web Tokens (JWTs), including ID tokens and access tokens.
 * It validates the claims in the tokens (such as audience and nonce) and ensures that the JWT is properly signed
 * using keys retrieved from a JWKS (JSON Web Key Set) endpoint. It uses an adaptor to decode the JWT and fetch keys.
 * The verification process also includes support for different token types (ID or access tokens).
 */

class JwtVerifier
{
    /**
     * @var string The issuer of the JWT token (e.g., Okta domain).
     */
    protected $issuer;

    /**
     * @var DiscoveryMethod The discovery method used to find the JWKS endpoint.
     */
    protected $discovery;

    /**
     * @var array The claims that should be validated in the JWT.
     */
    protected $claimsToValidate;

    /**
     * @var string The well-known URL used to fetch the metadata.
     */
    protected $wellknown;

    /**
     * @var mixed The metadata returned from the well-known URL.
     */
    protected $metaData;

    /**
     * @var Adaptor The adaptor used to decode and verify the JWT.
     */
    protected $adaptor;

    /**
     * @var string The URI for the JWKS (JSON Web Key Set).
     */
    protected string $jwksUri;

    /**
     * @var Request The HTTP request instance used for making requests.
     */
    private Request $request;

    /**
     * JwtVerifier constructor.
     *
     * @param string $issuer The issuer URL (e.g., Okta domain).
     * @param DiscoveryMethod|null $discovery The discovery method (optional, defaults to Oauth).
     * @param Adaptor|null $adaptor The adaptor for decoding and verifying the JWT (optional, defaults to AutoDiscover).
     * @param Request|null $request The HTTP request instance (optional).
     * @param int $leeway Time in seconds allowed for leeway during validation (optional, default is 120).
     * @param array $claimsToValidate List of claims to validate (optional).
     */
    public function __construct(
        string $issuer,
        DiscoveryMethod $discovery = null,
        Adaptor $adaptor = null,
        Request $request = null,
        int $leeway = 120,
        array $claimsToValidate = []
    ) {
        $this->issuer = $issuer;
        $this->discovery = $discovery ?: new Oauth;
        $this->adaptor = $adaptor ?: AutoDiscover::getAdaptor();
        $this->request = $request ?: new Request;
        $this->claimsToValidate = $claimsToValidate;
        $this->jwksUri = "$issuer/oauth2/v1/keys";
    }

    /**
     * Get the JWKS URI used for fetching the public keys.
     *
     * @return string The JWKS URI.
     */
    public function getJwksUri(): string
    {
        return $this->jwksUri;
    }

    /**
     * Get the issuer of the JWT token.
     *
     * @return string The issuer URL.
     */
    public function getIssuer(): string
    {
        return $this->issuer;
    }

    /**
     * Get the discovery method used to find the JWKS endpoint.
     *
     * @return DiscoveryMethod The discovery method.
     */
    public function getDiscovery()
    {
        return $this->discovery;
    }

    /**
     * Get metadata from the well-known URL.
     *
     * @deprecated This method is deprecated. You should no longer rely on this method for client metadata.
     * 
     * @return mixed The metadata in JSON format, fetched from the well-known URL.
     */
    public function getMetaData()
    {
        $this->wellknown = $this->issuer . $this->discovery->getWellKnown();
        return json_decode($this->request->setUrl($this->wellknown)->get()->getBody());
    }

    /**
     * Get the JSON Web Keys (JWKS) from the JWKS URI.
     *
     * @return array|mixed The keys fetched from the JWKS URI.
     */
    public function getKeys()
    {
        return $this->adaptor->getKeys($this->jwksUri);
    }

    /**
     * Verify the provided JWT (access token).
     *
     * This method verifies the JWT using the keys fetched from the JWKS URI and validates the claims.
     *
     * @param string $jwt The JWT to verify.
     * @return mixed The decoded JWT.
     * @throws \Exception If the verification or claim validation fails.
     */
    public function verify($jwt)
    {
        // Get the keys for verification
        $keys = $this->getKeys();

        // Decode the JWT using the appropriate adaptor
        $decoded = $this->adaptor->decode($jwt, $keys);

        // Validate claims based on the type of token (access token in this case)
        $this->validateClaims($decoded->getClaims(), "access");

        return $decoded;
    }

    /**
     * Verify the provided ID token.
     *
     * This method verifies the ID token using the keys fetched from the JWKS URI and validates the claims.
     *
     * @param string $jwt The ID token to verify.
     * @return mixed The decoded ID token.
     * @throws \Exception If the verification or claim validation fails.
     */
    public function verifyIdToken($jwt)
    {
        // Get the keys for verification
        $keys = $this->getKeys();

        // Decode the ID token using the appropriate adaptor
        $decoded = $this->adaptor->decode($jwt, $keys);

        // Validate claims based on the ID token type
        $this->validateClaims($decoded->getClaims(), "id");

        return $decoded;
    }

    /**
     * Verify the provided access token.
     *
     * This method verifies the access token using the keys fetched from the JWKS URI and validates the claims.
     *
     * @param string $jwt The access token to verify.
     * @return mixed The decoded access token.
     * @throws \Exception If the verification or claim validation fails.
     */
    public function verifyAccessToken($jwt)
    {
        // Get the keys for verification
        $keys = $this->getKeys();

        // Decode the access token using the appropriate adaptor
        $decoded = $this->adaptor->decode($jwt, $keys);

        // Validate claims based on the access token type
        $this->validateClaims($decoded->getClaims(), "access");

        return $decoded;
    }

    /**
     * Validate the claims in the decoded JWT.
     *
     * This method checks the claims based on the type of token (ID token or access token).
     *
     * @param array $claims The claims from the decoded JWT.
     * @param string $type The type of token ("id" or "access").
     * @throws \Exception If any of the claims are invalid.
     */
    private function validateClaims(array $claims, string $type)
    {
        switch ($type) {
            case 'id':
                $this->validateAudience($claims);
                $this->validateNonce($claims);
                break;
            case 'access':
                $this->validateAudience($claims);
                $this->validateClientId($claims);
                break;
        }
    }

    /**
     * Validate the 'nonce' claim.
     *
     * @param array $claims The claims from the decoded JWT.
     * @throws \Exception If the nonce does not match the expected value.
     */
    private function validateNonce($claims)
    {
        // Check if the 'nonce' claim exists and matches the expected value
        if (!isset($claims['nonce']) && $this->claimsToValidate['nonce'] == null) {
            return false;
        }

        if ($claims['nonce'] != $this->claimsToValidate['nonce']) {
            throw new \Exception('Nonce does not match what is expected. Make sure to provide the nonce with `setNonce()` from the JwtVerifierBuilder.');
        }
    }

    /**
     * Validate the 'audience' claim.
     *
     * @param array $claims The claims from the decoded JWT.
     * @throws \Exception If the audience does not match the expected value.
     */
    private function validateAudience($claims)
    {
        // Check if the 'aud' (audience) claim exists and matches the expected value
        if (!isset($claims['aud']) && $this->claimsToValidate['audience'] == null) {
            return false;
        }

        if ($claims['aud'] != $this->claimsToValidate['audience']) {
            throw new \Exception('Audience does not match what is expected. Make sure to provide the audience with `setAudience()` from the JwtVerifierBuilder.');
        }
    }

    /**
     * Validate the 'client_id' claim.
     *
     * @param array $claims The claims from the decoded JWT.
     * @throws \Exception If the client ID does not match the expected value.
     */
    private function validateClientId($claims)
    {
        // Check if the 'cid' (client ID) claim exists and matches the expected value
        if (!isset($claims['cid']) && $this->claimsToValidate['clientId'] == null) {
            return false;
        }

        if ($claims['cid'] != $this->claimsToValidate['clientId']) {
            throw new \Exception('ClientId does not match what is expected. Make sure to provide the client id with `setClientId()` from the JwtVerifierBuilder.');
        }
    }
}
