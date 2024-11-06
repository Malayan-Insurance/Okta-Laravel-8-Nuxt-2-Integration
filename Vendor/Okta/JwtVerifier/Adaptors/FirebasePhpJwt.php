<?php

namespace App\Vendor\Okta\JwtVerifier\Adaptors;

use Carbon\Carbon;
use Firebase\JWT\JWT as FirebaseJWT;
use Illuminate\Cache\ArrayStore;
use Firebase\JWT\Key;
use App\Vendor\Okta\JwtVerifier\Jwt;
use App\Vendor\Okta\JwtVerifier\Request;
use Psr\SimpleCache\CacheInterface;
use UnexpectedValueException;

/**
 * Class FirebasePhpJwt
 * 
 * This class implements the `Adaptor` interface and provides functionality for decoding
 * JSON Web Tokens (JWTs) using the Firebase JWT library. It also handles key retrieval
 * and caching for JWT validation, working with public keys from the JSON Web Key Set (JWKS).
 * It also includes logic for handling leeway and caching configurations.
 */
class FirebasePhpJwt implements Adaptor
{
    /** @var Request The request handler used for fetching the public keys. */
    private $request;

    /** @var CacheInterface The caching system used to store and retrieve public keys. */
    private $cache;

    /** @var int The leeway time in seconds for JWT validation. */
    private $leeway;

    /**
     * FirebasePhpJwt constructor.
     *
     * Initializes the FirebasePhpJwt instance with the provided request handler, leeway, 
     * and cache system. If no values are provided, default values are used.
     * 
     * @param Request|null $request The request handler used to fetch the public keys.
     * @param int $leeway The amount of leeway (in seconds) to allow for token expiration.
     * @param CacheInterface|null $cache The cache system to store keys.
     */
    public function __construct(Request $request = null, int $leeway = 120, CacheInterface $cache = null)
    {
        $this->request = $request ?: new Request();
        $this->leeway = $leeway ?: 120;
        $this->cache = $cache ?: new \Illuminate\Cache\Repository(new ArrayStore(true));
    }

    /**
     * Clears the cached public keys for a given JWKS URL.
     *
     * This method deletes the cached keys associated with the provided JSON Web Key Set
     * URL, forcing a fresh request for the keys the next time they are needed.
     * 
     * @param string $jku The JSON Web Key URL used to fetch the keys.
     * 
     * @return bool Whether the cache key was deleted successfully.
     */
    public function clearCache(string $jku)
    {
        $cacheKey = 'keys-' . md5($jku);
        return $this->cache->delete($cacheKey);
    }

    /**
     * Retrieves the public keys from the JWKS (JSON Web Key Set) endpoint.
     *
     * This method attempts to fetch the public keys from the cache first. If they are not 
     * available in the cache, it sends a request to the provided `jku` (JSON Web Key URL) 
     * to fetch the keys, then stores them in the cache for future use.
     * 
     * @param string $jku The JSON Web Key URL to fetch the keys from.
     * 
     * @return array The parsed public keys.
     */
    public function getKeys(string $jku): array
    {
        $cacheKey = 'keys-' . md5($jku);

        // Attempt to retrieve cached keys
        $cached = $this->cache->get($cacheKey);
        if ($cached) {
            return self::parseKeySet($cached);
        }

        // Fetch keys from the JWKS URL if not cached
        $keys = json_decode($this->request->setUrl($jku)->get()->getBody()->getContents());
        // Store the keys in the cache for 1 day
        $this->cache->set($cacheKey, $keys, Carbon::now()->addDay());

        return self::parseKeySet($keys);
    }

    /**
     * Decodes a JWT using the provided keys.
     *
     * This method decodes the given JWT using the provided public keys (as a Key object).
     * The decoded JWT is then returned as a `Jwt` object with the raw JWT and decoded claims.
     * 
     * @param string $jwt The JWT string to decode.
     * @param array $keys The public keys to use for decoding the JWT.
     * 
     * @return Jwt The decoded JWT as a `Jwt` object.
     */
    public function decode($jwt, $keys): Jwt
    {
        // Convert the keys to `Key` objects
        $keys = array_map(function ($key) {
            return new Key($key, 'RS256');
        }, $keys);

        // Decode the JWT using the provided keys
        $decoded = (array)FirebaseJWT::decode($jwt, $keys);
        return (new Jwt($jwt, $decoded));
    }

    /**
     * Checks if the Firebase JWT package is available.
     *
     * This static method checks if the `Firebase\JWT\JWT` class is available, 
     * indicating whether the Firebase JWT package is installed.
     * 
     * @return bool Whether the Firebase JWT package is available.
     */
    public static function isPackageAvailable()
    {
        return class_exists(FirebaseJWT::class);
    }

    /**
     * Parses a JSON Web Key Set (JWKS) and returns an array of keys.
     *
     * This method processes a JWKS, which is typically returned from a JKU endpoint, 
     * and parses the individual keys. The keys are returned as an array.
     * 
     * @param mixed $source The source data (could be a string, array, or object) containing the keys.
     * 
     * @return array The parsed keys.
     * 
     * @throws UnexpectedValueException If parsing the JWKS fails.
     */
    public static function parseKeySet($source)
    {
        $keys = [];
        // Ensure the source is an array
        if (is_string($source)) {
            $source = json_decode($source, true);
        } elseif (is_object($source)) {
            if (property_exists($source, 'keys')) {
                $source = (array)$source;
            } else {
                $source = [$source];
            }
        }
        if (is_array($source)) {
            // Extract keys if the 'keys' property is present
            if (isset($source['keys'])) {
                $source = $source['keys'];
            }

            // Parse each key in the set
            foreach ($source as $k => $v) {
                if (!is_string($k)) {
                    if (is_array($v) && isset($v['kid'])) {
                        $k = $v['kid'];
                    } elseif (is_object($v) && property_exists($v, 'kid')) {
                        $k = $v->{'kid'};
                    }
                }
                try {
                    $v = self::parseKey($v);
                    $keys[$k] = $v;
                } catch (UnexpectedValueException $e) {
                }
            }
        }

        // Ensure there are keys to return
        if (count($keys) > 0) {
            return $keys;
        }
        throw new UnexpectedValueException('Failed to parse JWK');
    }

    /**
     * Parses a single key from a JWKS.
     *
     * This method processes an individual key from a JWKS, verifying that it contains 
     * the required fields (e.g., `kty`, `n`, and `e` for RSA keys). It then attempts to 
     * create a valid public key object from the modulus and exponent.
     * 
     * @param mixed $source The key data to parse.
     * 
     * @return resource The parsed public key.
     * 
     * @throws UnexpectedValueException If the key is invalid or cannot be parsed.
     */
    public static function parseKey($source)
    {
        if (!is_array($source)) {
            $source = (array)$source;
        }
        if (!empty($source) && isset($source['kty']) && isset($source['n']) && isset($source['e'])) {
            switch ($source['kty']) {
                case 'RSA':
                    if (array_key_exists('d', $source)) {
                        throw new UnexpectedValueException('Failed to parse JWK: RSA private key is not supported');
                    }

                    // Generate PEM from modulus and exponent
                    $pem = self::createPemFromModulusAndExponent($source['n'], $source['e']);
                    $pKey = openssl_pkey_get_public($pem);
                    if ($pKey !== false) {
                        return $pKey;
                    }
                    break;
                default:
                    break;
            }
        }

        throw new UnexpectedValueException('Failed to parse JWK');
    }

    /**
     * Creates a PEM-encoded public key from modulus and exponent.
     *
     * This method constructs a PEM-formatted RSA public key from the modulus (`n`) and 
     * public exponent (`e`) provided in the JWK. The public key is returned in PEM format.
     * 
     * @param string $n The modulus (in base64url-encoded form).
     * @param string $e The public exponent (in base64url-encoded form).
     * 
     * @return string The PEM-encoded RSA public key.
     */
    private static function createPemFromModulusAndExponent($n, $e)
    {
        $modulus = FirebaseJWT::urlsafeB64Decode($n);
        $publicExponent = FirebaseJWT::urlsafeB64Decode($e);

        // Pack components for the RSA public key
        $components = array(
            'modulus' => pack('Ca*a*', 2, self::encodeLength(strlen($modulus)), $modulus),
            'publicExponent' => pack('Ca*a*', 2, self::encodeLength(strlen($publicExponent)), $publicExponent)
        );

        // Combine the components into the full RSA public key
        $RSAPublicKey = pack(
            'Ca*a*a*',
            48,
            self::encodeLength(strlen($components['modulus']) + strlen($components['publicExponent'])),
            $components['modulus'],
            $components['publicExponent']
        );

        // Add RSA OID and prepare final key
        $rsaOID = pack('H*', '300d06092a864886f70d0101010500');
        $RSAPublicKey = chr(0) . $RSAPublicKey;
        $RSAPublicKey = chr(3) . self::encodeLength(strlen($RSAPublicKey)) . $RSAPublicKey;

        $RSAPublicKey = pack(
            'Ca*a*',
            48,
            self::encodeLength(strlen($rsaOID . $RSAPublicKey)),
            $rsaOID . $RSAPublicKey
        );

        // Return the final PEM key
        $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
            chunk_split(base64_encode($RSAPublicKey), 64) .
            '-----END PUBLIC KEY-----';

        return $RSAPublicKey;
    }

    /**
     * Encodes the length of a given value.
     *
     * This method encodes the length of the given value as a BER-encoded length,
     * which is used in the construction of the RSA public key.
     * 
     * @param int $length The length to encode.
     * 
     * @return string The encoded length.
     */
    private static function encodeLength($length)
    {
        if ($length <= 0x7F) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }
}
