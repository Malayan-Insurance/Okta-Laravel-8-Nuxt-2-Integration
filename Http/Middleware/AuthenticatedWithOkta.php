<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class AuthenticatedWithOkta
{
    /**
     * Handle an incoming request and verify if the request is authorized.
     *
     * This middleware checks if the request contains a valid Bearer token in the Authorization header.
     * If the token is valid, the request is passed to the next middleware/handler.
     * If the token is invalid or missing, an "Unauthorized" response with a 401 status code is returned.
     *
     * @param Request $request The incoming HTTP request instance.
     * @param Closure $next The next middleware/handler to pass the request to.
     * @return \Illuminate\Http\Response|\Illuminate\Http\JsonResponse The response from the next middleware or an error response.
     */
    public function handle(Request $request, Closure $next)
    {
        // Check if the request is authorized
        if ($this->isAuthorized($request)) {
            // If authorized, continue processing the request
            return $next($request);
        } else {
            // If not authorized, return a 401 Unauthorized response
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    /**
     * Verify if the request has a valid Bearer token.
     *
     * This method checks the Authorization header of the request for a Bearer token.
     * If the token is present and valid according to Okta's JWT verification service, 
     * it returns true; otherwise, it returns false.
     *
     * @param Request $request The incoming HTTP request instance.
     * @return bool Returns true if the request contains a valid Bearer token, otherwise false.
     */
    private function isAuthorized(Request $request): bool
    {
        // Get the Authorization header from the request
        $authHeader = $request->header('Authorization');

        // If the Authorization header is not present, return false (unauthorized)
        if (!$authHeader) {
            return false;
        }

        // Split the Authorization header into its two components: [Bearer, token]
        $parts = explode(" ", $authHeader);

        // Check if the header has exactly two parts and the first part is "Bearer"
        if (count($parts) !== 2 || $parts[0] !== "Bearer") {
            return false;
        }

        // Extract the token from the header
        $token = $parts[1];

        try {
            // Build the JWT verifier using Okta's JWT Verifier
            $jwtVerifier = (new \App\Vendor\Okta\JwtVerifier\JwtVerifierBuilder())
                ->setAdaptor(new \App\Vendor\Okta\JwtVerifier\Adaptors\FirebasePhpJwt()) // JWT decoding library (Firebase)
                ->setClientId(env('OKTA_CLIENT_ID'))  // Okta Client ID from environment
                ->setAudience(env('OKTA_DOMAIN'))    // Okta domain as audience
                ->setIssuer(env('OKTA_DOMAIN'))      // Okta domain as issuer
                ->build(); // Build the verifier instance

            // Verify the token with the Okta JwtVerifier
            $jwt = $jwtVerifier->verify($token);
        } catch (\Exception $e) {
            // In case of an error (invalid token or verification failure), return false
            return false;
        }
        return true;
    }
}
