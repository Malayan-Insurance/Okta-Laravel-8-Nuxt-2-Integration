<?php

namespace App\Vendor\Okta\JwtVerifier\Discovery;

use App\Vendor\Okta\JwtVerifier\Discovery\DiscoveryMethod as Discovery;

/**
 * Class Oidc
 *
 * This class extends the DiscoveryMethod class and represents an OIDC (OpenID Connect) 
 * discovery method. It is responsible for handling the OIDC-specific discovery mechanism,
 * such as providing the URI to fetch the OpenID Connect configuration (the `.well-known/openid-configuration`).
 */
class Oidc extends Discovery
{
    /** @var string The URI path to the OpenID Connect discovery document. */
    protected $wellKnownUri = '/.well-known/openid-configuration';

    /**
     * Get the well-known URI for the OpenID Connect configuration.
     *
     * This method returns the URI path that is typically used to retrieve the OpenID 
     * Connect configuration. This is part of the OIDC discovery mechanism, which is 
     * used to retrieve configuration information such as the authorization server's 
     * endpoint locations, supported features, and public keys.
     *
     * @return string The well-known URI for OpenID Connect configuration.
     */
    public function getWellKnownUri(): string
    {
        // Return the well-known URI for the OpenID Connect configuration
        return $this->wellKnownUri;
    }
}
