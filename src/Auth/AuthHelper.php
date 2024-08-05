<?php

namespace GestionKronos\Oauth\Auth;

use Carbon\Carbon;

class AuthHelper
{
    public static function GenerateSecretHash(
        string $username,
        string $client_id,
        string $pool_id,
        string $pool_secret,
        string $client_secret
    ): string {
        $time_hash = Carbon::today()->setTime(12, 0, 0)->timestamp;
        $message = $time_hash . $pool_id . $username . $client_id;
        $enc_key = $pool_secret . $client_secret . $time_hash;
        return base64_encode(hash_hmac('sha256', $message, $enc_key, true));
    }
}