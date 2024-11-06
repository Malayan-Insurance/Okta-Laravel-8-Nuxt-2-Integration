# Okta JWT Verifier

A PHP package for verifying JWTs (JSON Web Tokens) issued by Okta authorization servers. This package provides functionality to decode and validate JWTs, ensuring that they are properly signed and that claims such as `issuer`, `audience`, `clientId`, and `nonce` are validated.

## Table of Contents
- [Project Overview](#project-overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Usage](#basic-usage)
  - [Advanced Configuration](#advanced-configuration)
- [Error Handling](#error-handling)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Project Overview

This package allows for the verification of JWTs issued by Okta by configuring parameters like issuer, audience, leeway, and client ID. It uses [Guzzle](https://docs.guzzlephp.org/en/stable/) for HTTP requests and provides a flexible builder pattern for creating the `JwtVerifier` instance.

## Features

- **Issuer Validation**: Ensures that the JWT was issued by a trusted Okta authorization server.
- **Audience Validation**: Ensures that the JWT is intended for the correct audience.
- **Leeway Handling**: Configures expiration tolerance using ISO 8601 duration format.
- **Discovery Endpoint**: Allows the retrieval of JWKS (JSON Web Key Set) using Okta's discovery endpoint.
- **Modular**: Built with a flexible builder pattern for custom configuration.