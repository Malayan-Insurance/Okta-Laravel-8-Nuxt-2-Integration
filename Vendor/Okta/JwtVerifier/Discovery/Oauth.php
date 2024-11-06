<?php

namespace App\Vendor\Okta\JwtVerifier\Discovery;

use App\Vendor\Okta\JwtVerifier\Discovery\DiscoveryMethod as Discovery;

/**
 * Class Oauth
 *
 * This class extends the DiscoveryMethod class and represents an OAuth 2.0 discovery 
 * method. It handles the OAuth-specific discovery mechanism, particularly for 
 * retrieving the OAuth authorization server configuration, using the 
 * `.well-known/oauth-authorization-server` endpoint.
 */
class Oauth extends Discovery
{
    /** @var string The URI path to the OAuth 2.0 authorization server configuration. */
    protected $wellKnownUri = '/.well-known/oauth-authorization-server';

    /**
     * Get the well-known URI for the OAuth 2.0 authorization server configuration.
     *
     * This method returns the URI that is used to discover OAuth 2.0 authorization server 
     * configuration. This is part of the OAuth 2.0 discovery process, which provides 
     * the configuration necessary for interacting with the OAuth authorization server, 
     * such as endpoint URLs and supported features.
     *
     * @return string The well-known URI for OAuth 2.0 authorization server configuration.
     */
    public function getWellKnownUri(): string
    {
        // Return the well-known URI for the OAuth 2.0 authorization server configuration.
        return $this->wellKnownUri;
    }
}
