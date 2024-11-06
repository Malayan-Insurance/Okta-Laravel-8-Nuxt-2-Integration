<?php

namespace App\Vendor\Okta\JwtVerifier;

use App\Vendor\Okta\JwtVerifier\Adaptors\Adaptor;
use App\Vendor\Okta\JwtVerifier\Discovery\DiscoveryMethod;
use Bretterer\IsoDurationConverter\DurationParser;

/**
 * Class JwtVerifierBuilder
 *
 * A builder class for configuring and constructing a JwtVerifier instance.
 * This allows flexible configuration of JWT verification settings including issuer,
 * discovery methods, claims validation (audience, clientId, nonce), and expiration leeway.
 */
class JwtVerifierBuilder
{
    /**
     * @var string The issuer of the JWT (e.g., Okta domain).
     */
    protected $issuer;

    /**
     * @var DiscoveryMethod The discovery method used to retrieve the JWKS (JSON Web Key Set) endpoint.
     */
    protected $discovery;

    /**
     * @var Request The request instance used for making HTTP requests (optional).
     */
    protected $request;

    /**
     * @var Adaptor The adaptor used to decode and verify JWTs.
     */
    protected $adaptor;

    /**
     * @var string The audience claim to be validated in the JWT.
     */
    protected $audience;

    /**
     * @var string The client ID claim to be validated in the JWT.
     */
    protected $clientId;

    /**
     * @var string The nonce claim to be validated in the JWT.
     */
    protected $nonce;

    /**
     * @var int The leeway (in seconds) for token expiration validation (default: 120 seconds).
     */
    protected $leeway = 120;

    /**
     * JwtVerifierBuilder constructor.
     * 
     * Initializes the builder with an optional Request instance for HTTP requests.
     * 
     * @param Request|null $request The HTTP request instance (optional).
     */
    public function __construct(Request $request = null)
    {
        $this->request = $request;
    }

    /**
     * Set the issuer URL for JWT verification.
     * 
     * @param string $issuer The issuer URL (e.g., Okta domain).
     * @return $this The current instance of the builder, allowing method chaining.
     */
    public function setIssuer(string $issuer): self
    {
        $this->issuer = rtrim($issuer, "/"); // Ensure the issuer does not end with a trailing slash.

        return $this;
    }

    /**
     * Set the discovery method used to retrieve the JWKS endpoint.
     * 
     * @param DiscoveryMethod $discoveryMethod The discovery method to use.
     * @return $this The current instance of the builder, allowing method chaining.
     */
    public function setDiscovery(DiscoveryMethod $discoveryMethod): self
    {
        $this->discovery = $discoveryMethod;

        return $this;
    }

    /**
     * Set the adaptor to be used for decoding and verifying the JWT.
     * 
     * @param Adaptor $adaptor The adaptor for decoding and verifying the JWT.
     * @return $this The current instance of the builder, allowing method chaining.
     */
    public function setAdaptor(Adaptor $adaptor): self
    {
        $this->adaptor = $adaptor;

        return $this;
    }

    /**
     * Set the audience claim to be validated in the JWT.
     * 
     * @param string $audience The audience claim (e.g., the Okta client ID).
     * @return $this The current instance of the builder, allowing method chaining.
     */
    public function setAudience($audience)
    {
        $this->audience = $audience;

        return $this;
    }

    /**
     * Set the client ID claim to be validated in the JWT.
     * 
     * @param string $clientId The client ID claim to validate.
     * @return $this The current instance of the builder, allowing method chaining.
     */
    public function setClientId($clientId)
    {
        $this->clientId = $clientId;

        return $this;
    }

    /**
     * Set the nonce claim to be validated in the JWT.
     * 
     * @param string $nonce The nonce claim to validate.
     * @return $this The current instance of the builder, allowing method chaining.
     */
    public function setNonce($nonce)
    {
        $this->nonce = $nonce;

        return $this;
    }

    /**
     * Set the leeway for token expiration validation, specified in ISO 8601 duration format.
     * 
     * The leeway is used to allow some flexibility in token expiration validation. The duration should be in ISO 8601 format (e.g., "PT2M" for 2 minutes).
     * 
     * @param string $leeway The leeway duration (e.g., "PT2M" for 2 minutes).
     * @return $this The current instance of the builder, allowing method chaining.
     * @throws \InvalidArgumentException If the provided leeway is not in ISO 8601 duration format.
     */
    public function setLeeway(string $leeway = "PT2M"): self
    {
        // Validate the format of the leeway duration
        if (strstr($leeway, "P")) {
            $msg = "It appears that the leeway provided is not in ISO_8601 Duration Format.";
            $msg .= " Please provide a duration in the format of `PT(n)S`.";
            throw new \InvalidArgumentException($msg);
        }

        // Parse the duration using the DurationParser
        $leeway = (new DurationParser)->parse($leeway);
        $this->leeway = $leeway;

        return $this;
    }

    /**
     * Build the JwtVerifier instance with the configured settings.
     * 
     * This method will validate the issuer and client ID before creating and returning a new instance of the JwtVerifier.
     * 
     * @return JwtVerifier The JwtVerifier instance with the specified configurations.
     * @throws \InvalidArgumentException If the issuer or client ID are not set correctly.
     */
    public function build(): JwtVerifier
    {
        // Validate the issuer and client ID to ensure they are set correctly
        $this->validateIssuer($this->issuer);
        $this->validateClientId($this->clientId);

        // Return a new instance of JwtVerifier with the configured settings
        return new JwtVerifier(
            $this->issuer,
            $this->discovery,
            $this->adaptor,
            $this->request,
            $this->leeway,
            [
                'nonce' => $this->nonce,
                'audience' => $this->audience,
                'clientId' => $this->clientId
            ]
        );
    }

    /**
     * Validate the issuer URL.
     * 
     * This method checks if the issuer is correctly configured, including validation for HTTPS and placeholders.
     * 
     * @param string $issuer The issuer URL to validate.
     * @throws \InvalidArgumentException If the issuer is invalid or missing.
     */
    private function validateIssuer($issuer): void
    {
        // Ensure the issuer is not null or empty
        if (null === $issuer || "" == $issuer) {
            $msg = "Your Issuer is missing. ";
            $msg .= "You can find your issuer from your authorization server settings in the Okta Developer Console. ";
            $msg .= "Find out more information about Authorization Servers at ";
            $msg .= "https://developer.okta.com/docs/guides/customize-authz-server/overview/";
            throw new \InvalidArgumentException($msg);
        }

        // Ensure the issuer starts with https
        if (strstr($issuer, "https://") == false) {
            $msg = "Your Issuer must start with https. Current value: {$issuer}. ";
            $msg .= "You can copy your issuer from your authorization server settings in the Okta Developer Console. ";
            $msg .= "Find out more information about Authorization Servers at ";
            $msg .= "https://developer.okta.com/docs/guides/customize-authz-server/overview/";
            throw new \InvalidArgumentException($msg);
        }

        // Ensure the issuer does not contain a placeholder like {yourOktaDomain}
        if (strstr($issuer, "{yourOktaDomain}") != false) {
            $msg = "Replace {yourOktaDomain} with your Okta domain. ";
            $msg .= "You can copy your domain from the Okta Developer Console. Follow these instructions to find it: ";
            $msg .= "https://bit.ly/finding-okta-domain";
            throw new \InvalidArgumentException($msg);
        }
    }

    /**
     * Validate the client ID.
     * 
     * This method ensures that the client ID is correctly configured and does not contain placeholders.
     * 
     * @param string $cid The client ID to validate.
     * @throws \InvalidArgumentException If the client ID is missing or invalid.
     */
    private function validateClientId($cid): void
    {
        // Ensure the client ID is not null or empty
        if (null === $cid || "" == $cid) {
            $msg = "Your client ID is missing. You can copy it from the Okta Developer Console in the details for the ";
            $msg .= "Application you created. Follow these instructions to find it: ";
            $msg .= "https://bit.ly/finding-okta-app-credentials";
            throw new \InvalidArgumentException($msg);
        }

        // Ensure the client ID does not contain a placeholder like {clientId}
        if (strstr($cid, "{clientId}") != false) {
            $msg = "Replace {clientId} with the client ID of your Application. You can copy it from the Okta Developer";
            $msg .= " Console in the details for the Application you created. Follow these instructions to find it: ";
            $msg .= "https://bit.ly/finding-okta-app-credentials";
            throw new \InvalidArgumentException($msg);
        }
    }
}
