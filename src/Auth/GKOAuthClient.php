<?php

namespace GestionKronos\Oauth\Auth;

use GestionKronos\Oauth\Auth\Entities\AuthFlow;
use GestionKronos\Oauth\Auth\Entities\GrantType;

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
        AuthFlow $auth_flow,
        string|null $username = null,
        string|null $password = null,
        string $access_token = null,
    ) {
        $auth_parameters = [
            "client_id" => $this->client_id,
            "pool_id" => $this->pool_id,
            "auth_flow" => $auth_flow->value,
            "callback_uri" => $this->callback_uri,
            "auth_parameters" => [
                "secret_hash" => $secret_hash,
                "grant_type" => $grant_type,
            ]
        ];

        if ($auth_flow === AuthFlow::IMPERSONATE) {
            if (!$username) {
                return json_encode([
                    'message' => 'INVALID_OR_MISSING_FIELDS',
                    'description' => 'Invalid or missing form data. Please refer to api documentation for further instructions',
                ]);
            }

            $auth_parameters['auth_parameters']['username'] = $username;
        }


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

        $curl_params = [
            CURLOPT_URL => 'http://127.0.0.1:8000/api/initiate-auth',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 100,
            CURLOPT_TIMEOUT => 300,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => http_build_query($auth_parameters)
        ];

        if ($auth_flow === AuthFlow::IMPERSONATE) {
            $curl_params[CURLOPT_HTTPHEADER] = [
                'Accept: application/json',
                'Authorization: Bearer ' . $access_token
            ];
        }

        curl_setopt_array($curl, $curl_params);

        $response = curl_exec($curl);
        $err = curl_error($curl);

        if ($auth_flow === AuthFlow::IMPERSONATE) {
            \Log::error(json_encode($response));
        }

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
        AuthFlow $auth_flow,
        string $username,
        string $access_token,
    ) {
        $auth_parameters = [
            "client_id" => $this->client_id,
            "pool_id" => $this->pool_id,
            "auth_flow" => $auth_flow->value,
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

        return $response_data;
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
}
