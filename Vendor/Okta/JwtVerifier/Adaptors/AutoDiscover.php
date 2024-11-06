<?php

namespace App\Vendor\Okta\JwtVerifier\Adaptors;

/**
 * Class AutoDiscover
 *
 * This class is responsible for automatically discovering and returning the appropriate
 * JWT adaptor based on the available JWT libraries in the system. It checks the availability
 * of supported adaptors (such as `FirebasePhpJwt`) and returns an instance of the first
 * adaptor that is available. If no suitable adaptor is found, it throws an exception.
 */
class AutoDiscover
{
    /** @var array List of supported JWT adaptors to check for availability. */
    private static $adaptors = [
        FirebasePhpJwt::class
    ];

    /**
     * Discover and return the first available JWT adaptor.
     *
     * This method loops through the list of adaptors and checks whether the corresponding
     * JWT library (such as `FirebasePhpJwt`) is available using the `isPackageAvailable` method.
     * If an available adaptor is found, it returns a new instance of that adaptor.
     * If no adaptors are available, an exception is thrown.
     * 
     * @return object An instance of a JWT adaptor (e.g., `FirebasePhpJwt`).
     * 
     * @throws \Exception If no compatible JWT library is found.
     */
    public static function getAdaptor()
    {
        // Loop through the list of available adaptors
        foreach (self::$adaptors as $adaptor) {
            // Check if the adaptor's package is available
            if ($adaptor::isPackageAvailable()) {
                // Return an instance of the available adaptor
                return new $adaptor();
            }
        }

        // If no adaptor is available, throw an exception
        throw new \Exception(
            'Could not discover JWT Library. ' .
            'Please make sure one is included and the Adaptor is used.'
        );
    }
}
