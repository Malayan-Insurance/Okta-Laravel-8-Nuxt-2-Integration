<?php

namespace App\Vendor\Okta\JwtVerifier;

use GuzzleHttp\Client;
use Psr\Http\Message\ResponseInterface;

/**
 * Class Request
 *
 * This class is a wrapper for making HTTP requests using Guzzle. It allows you to send GET (and potentially other HTTP methods) requests
 * to a given URL with optional query parameters. It is designed to be flexible and support method chaining.
 */
class Request
{
    /**
     * @var Client The HTTP client used for making requests.
     */
    protected $httpClient;

    /**
     * @var string The URL for the request.
     */
    protected $url;

    /**
     * @var array The query parameters to be included in the request.
     */
    protected $query = [];

    /**
     * Request constructor.
     * 
     * Initializes the Request class with the provided Guzzle HTTP client.
     * If no HTTP client is provided, a new instance of Guzzle's Client will be created.
     *
     * @param Client|null $httpClient The Guzzle HTTP client to use for requests. If none is provided, a new instance will be created.
     */
    public function __construct(Client $httpClient = null)
    {
        // Use the provided HTTP client or create a new instance if not provided.
        $this->httpClient = $httpClient ?: new Client();
    }

    /**
     * Set the URL for the request.
     * 
     * This method allows you to specify the URL to which the request will be sent.
     *
     * @param string $url The URL to send the request to.
     * @return Request The current instance of the Request class, allowing for method chaining.
     */
    public function setUrl($url): Request
    {
        $this->url = $url;
        return $this;
    }

    /**
     * Add a query parameter to the request.
     * 
     * This method allows you to add query parameters to the request. You can chain this method to add multiple parameters.
     * 
     * @param string $key The query parameter key.
     * @param mixed $value The value for the query parameter. Can be null.
     * @return Request The current instance of the Request class, allowing for method chaining.
     */
    public function withQuery($key, $value = null): Request
    {
        $this->query[$key] = $value;
        return $this;
    }

    /**
     * Send a GET request to the set URL with any query parameters.
     * 
     * This method sends a GET request to the specified URL and includes any query parameters that have been set.
     * 
     * @return ResponseInterface The response from the HTTP request.
     */
    public function get(): ResponseInterface
    {
        return $this->request('GET');
    }

    /**
     * Perform an HTTP request with the given method (e.g., GET, POST, etc.).
     * 
     * This method sends the HTTP request using the Guzzle client with the specified HTTP method and any query parameters
     * that have been set.
     *
     * @param string $method The HTTP method to use for the request (GET, POST, etc.).
     * @return ResponseInterface The response from the HTTP request.
     */
    protected function request($method): ResponseInterface
    {
        // If query parameters exist, include them in the request options.
        $options = !empty($this->query) ? ['query' => $this->query] : [];

        // Send the HTTP request using the Guzzle HTTP client.
        return $this->httpClient->request($method, $this->url, $options);
    }
}
