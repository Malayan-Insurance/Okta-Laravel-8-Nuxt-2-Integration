<?php

namespace App\Vendor\Okta\JwtVerifier\Discovery;

/**
 * Class DiscoveryMethod
 *
 * This is an abstract class that provides the foundational mechanism for handling
 * discovery methods in OAuth 2.0 and OpenID Connect (OIDC) configurations. It includes
 * the common logic for managing the well-known URI used for retrieving discovery 
 * documents, such as the OpenID Connect and OAuth 2.0 configurations.
 * 
 * This class is meant to be extended by concrete discovery classes (e.g., `Oidc` and `Oauth`),
 * which implement specific logic for retrieving their respective discovery documents.
 */
abstract class DiscoveryMethod
{
    /** @var string The URI path for the well-known discovery document. */
    protected $wellKnownUri;

    /**
     * Get the well-known URI for the discovery document.
     *
     * This method returns the well-known URI that points to the discovery document, 
     * which contains information like the endpoints and configuration for OAuth 2.0 
     * or OpenID Connect. Subclasses (like OIDC or OAuth) should set this URI 
     * according to the specific discovery mechanism they are implementing.
     *
     * @return string The well-known URI for the discovery document.
     */
    public function getWellKnown()
    {
        // Return the URI for the well-known discovery document
        return $this->wellKnownUri;
    }
}
