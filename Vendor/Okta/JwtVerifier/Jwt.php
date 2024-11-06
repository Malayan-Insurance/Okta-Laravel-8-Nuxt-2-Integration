<?php

namespace App\Vendor\Okta\JwtVerifier;

/**
 * Class Jwt
 * 
 * This class is used to handle and manipulate JSON Web Tokens (JWT) and their claims.
 * It provides functionality to get the JWT, claims, and extract specific information like
 * expiration time and issued at time. It also provides a method to convert the claims to JSON.
 */
class Jwt
{
    /** @var string The JWT string. */
    private $jwt;

    /** @var array The claims contained within the JWT. */
    private $claims;

    /**
     * Jwt constructor.
     *
     * Initializes the Jwt object with a JWT string and an array of claims.
     * 
     * @param string $jwt The JWT string.
     * @param array $claims An associative array containing the claims.
     */
    public function __construct(
        string $jwt,
        array $claims
    ) {
        $this->jwt = $jwt;
        $this->claims = $claims;
    }

    /**
     * Get the JWT string.
     *
     * @return string The JWT string.
     */
    public function getJwt()
    {
        return $this->jwt;
    }

    /**
     * Get the claims associated with the JWT.
     *
     * @return array The claims array.
     */
    public function getClaims()
    {
        return $this->claims;
    }

    /**
     * Get the expiration time from the JWT claims.
     *
     * This method returns the expiration time of the JWT. If Carbon is available,
     * it returns a Carbon instance, otherwise it returns the timestamp directly.
     *
     * @param bool $carbonInstance Whether to return the expiration time as a Carbon instance.
     * 
     * @return int|\Carbon\Carbon The expiration time, either as a timestamp or a Carbon instance.
     */
    public function getExpirationTime($carbonInstance = true)
    {
        // Retrieve the 'exp' claim (expiration time) from the claims.
        $ts = $this->toJson()->exp;

        // If Carbon is available and the carbonInstance flag is true, return as a Carbon instance.
        if (class_exists(\Carbon\Carbon::class) && $carbonInstance) {
            return \Carbon\Carbon::createFromTimestampUTC($ts);
        }

        // Otherwise, return the timestamp directly.
        return $ts;
    }

    /**
     * Get the issued-at time from the JWT claims.
     *
     * This method returns the issued-at time of the JWT. Similar to getExpirationTime,
     * it can return a Carbon instance if available, or just the timestamp.
     *
     * @param bool $carbonInstance Whether to return the issued-at time as a Carbon instance.
     * 
     * @return int|\Carbon\Carbon The issued-at time, either as a timestamp or a Carbon instance.
     */
    public function getIssuedAt($carbonInstance = true)
    {
        // Retrieve the 'iat' claim (issued at time) from the claims.
        $ts = $this->toJson()->iat;

        // If Carbon is available and the carbonInstance flag is true, return as a Carbon instance.
        if (class_exists(\Carbon\Carbon::class) && $carbonInstance) {
            return \Carbon\Carbon::createFromTimestampUTC($ts);
        }

        // Otherwise, return the timestamp directly.
        return $ts;
    }

    /**
     * Convert the claims to a JSON object.
     *
     * This method converts the claims array into a JSON object. If the claims
     * is a resource (which cannot be converted to JSON), it throws an exception.
     *
     * @return object The claims as a JSON object.
     * 
     * @throws \InvalidArgumentException If the claims cannot be converted to JSON.
     */
    public function toJson()
    {
        // Check if the claims is a resource, which cannot be converted to JSON.
        if (is_resource($this->claims)) {
            throw new \InvalidArgumentException('Could not convert to JSON');
        }

        // Return the claims as a JSON object by first encoding and then decoding it.
        return json_decode(json_encode($this->claims));
    }
}
