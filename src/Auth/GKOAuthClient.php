<?php

namespace GestionKronos\Oauth\Auth;

use GestionKronos\Oauth\Auth\Entities\AuthFlow;
use GestionKronos\Oauth\Auth\Entities\GrantType;
use GestionKronos\Oauth\Auth\Helpers\Helper;

class GKOAuthClient
{
    public function __construct(
        protected string $client_id,
        protected string $pool_id,
        protected string $callback_uri,
    ) {}

    public function InitiateAuth(
        string $secret_hash,
        string $grant_type,
        string $auth_flow,
        string|null $username = null,
        string|null $password = null
    ) {
        $auth_parameters = [
            "client_id" => $this->client_id,
            "pool_id" => $this->pool_id,
            "auth_flow" => $auth_flow,
            "callback_uri" => $this->callback_uri,
            "auth_parameters" => [
                "secret_hash" => $secret_hash,
                "grant_type" => $grant_type,
                "username" => $username,
                "password" => $password,
            ]
        ];

        if ($auth_flow === AuthFlow::USER_PASSWORD) {
            if (!$password || !$username) {
                return json_encode([
                    'message' => 'INVALID_OR_MISSING_FIELDS',
                    'description' => 'Invalid or missing form data. Please refer to api documentation for further instructions',
                ]);
            }

            $auth_parameters['auth_parameters']['password'] = $password;
            $auth_parameters['auth_parameters']['username'] = $username;
        }

        $curl = curl_init();

        curl_setopt_array($curl, [
            CURLOPT_URL => 'http://127.0.0.1:8000/api/initiate-auth',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 100,
            CURLOPT_TIMEOUT => 300,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => http_build_query($auth_parameters),
            CURLOPT_HTTPHEADER => [
                'Accept: application/json'
            ],
        ]);

        $response = curl_exec($curl);
        $err = curl_error($curl);

        curl_close($curl);

        if ($err) {
            return "cURL Error #: " . $err;
        } else {
            return json_decode($response, true);
        }
    }

    public function AuthChallenge(
        string $secret_hash,
        string $grant_type,
        string $challenge_response,
        string $auth_flow,
        string $username,
        string $access_token,
        string $target_user_id = null
    ) {
        $auth_parameters = [
            "client_id" => $this->client_id,
            "pool_id" => $this->pool_id,
            "auth_flow" => $auth_flow,
            "callback_uri" => $this->callback_uri,
            "auth_parameters" => [
                "secret_hash" => $secret_hash,
                "grant_type" => $grant_type,
                "challenge_response" => $challenge_response,
                "username" => $username,
            ]
        ];

        $curl = curl_init();

        curl_setopt_array($curl, [
            CURLOPT_URL => 'http://127.0.0.1:8000/api/auth-challenge',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 100,
            CURLOPT_TIMEOUT => 300,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => http_build_query($auth_parameters),
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'Authorization: Bearer ' . $access_token
            ],
        ]);

        $response = curl_exec($curl);

        $err = curl_error($curl);

        curl_close($curl);

        if ($err) {
            return json_encode([
                "message" => "CURL_ERROR",
                "description" => "cURL Error #:" . $err
            ]);
        }

        $response_data = json_decode($response, true);

        if (isset($response_data["error"])) {
            if (str_contains(strtolower($response_data["error"]), "totp")) {
                return json_encode([
                    "message" => "INVALID_TOTP_CODE",
                    "description" => "The TOTP code given is either expired or invalid. Please try again.",
                ]);
            }

            return json_encode([
                "message" => "AUTHENTICATION_FAILED",
                "description" => "An error occurred while attempting to authenticate",
            ]);
        }

        setcookie(
            $response_data["token"]["access_token"]["type"],
            $response_data["token"]["access_token"]["token"],
            $response_data["token"]["access_token"]["duration"] / 60,
            '/',
            parse_url($this->callback_uri, PHP_URL_HOST),
            true,
            true
        );

        setcookie('X-AUTH-CHALLENGE', '', time() - 3600, '/');

        return json_encode([
            'message' => 'AUTHENTICATION_SUCCESS',
            'description' => 'You have been successfully logged in. Welcome Back!',
        ]);
    }

    public function InitiatePasswordReset(
        string $secret_hash,
        string $username,
    ) {
        $auth_parameters = [
            "client_id" => $this->client_id,
            "pool_id" => $this->pool_id,
            "callback_uri" => $this->callback_uri,
            "auth_parameters" => [
                "secret_hash" => $secret_hash,
                "username" => $username,
            ]
        ];

        if (!$username) {
            return json_encode([
                'message' => 'INVALID_OR_MISSING_FIELDS',
                'description' => 'Invalid or missing form data. Please refer to api documentation for further instructions',
            ]);
        }

        $auth_parameters['auth_parameters']['username'] = $username;

        $curl = curl_init();

        curl_setopt_array($curl, [
            CURLOPT_URL => 'http://127.0.0.1:8000/api/initiate-password-reset',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 100,
            CURLOPT_TIMEOUT => 300,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => http_build_query($auth_parameters),
            CURLOPT_HTTPHEADER => [
                'Accept: application/json'
            ],
        ]);

        $response = curl_exec($curl);
        $err = curl_error($curl);

        curl_close($curl);

        if ($err) {
            return "cURL Error #: " . $err;
        } else {
            return json_decode($response, true);
        }
    }

    public function ManageDataEncryption(
        string $secret_hash,
        string $auth_flow,
        string $data,
        string|null $username = null,
    ) {
        $auth_parameters = [
            "client_id" => $this->client_id,
            "pool_id" => $this->pool_id,
            "auth_flow" => $auth_flow,
            "callback_uri" => $this->callback_uri,
            "data" => $data,
            "auth_parameters" => [
                "secret_hash" => $secret_hash,
                "username" => $username,
            ]
        ];

        $route_prefix = Helper::GenerateRoutePrefixSecretHash(
            $username,
            $this->client_id,
            $this->pool_id
        );

        $route = Helper::GenerateRouteSecretHash(
            $username,
            $this->pool_id
        );

        $curl = curl_init();

        curl_setopt_array($curl, [
            CURLOPT_URL => `http://127.0.0.1:8000/api/{$route_prefix}/{$route}`,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 100,
            CURLOPT_TIMEOUT => 300,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => http_build_query($auth_parameters),
            CURLOPT_HTTPHEADER => [
                'Accept: application/json'
            ],
        ]);

        $response = curl_exec($curl);
        $err = curl_error($curl);

        curl_close($curl);

        if ($err) {
            return "cURL Error #: " . $err;
        } else {
            return json_decode($response, true);
        }
    }
}
