<?php

namespace GestionKronos\Oauth\Auth\Helpers;


class Helper
{
    public static function GenerateRoutePrefixSecretHash(
        string $username,
        string $client_id,
        string $pool_id,
    ): string {
        $date = new \DateTime();
        $date->setTime(12, 0, 0);
        $time_hash = $date->getTimestamp();

        $message = $pool_id . $time_hash .  $client_id;
        $enc_key = $username . $time_hash . $pool_id;
        $hash = base64_encode(hash_hmac('sha256', $message, $enc_key, true));

        return strtr($hash, '+/', '-_');
    }

    public static function GenerateRouteSecretHash(
        string $username,
        string $pool_id,
    ): string {
        $date = new \DateTime();
        $date->setTime(12, 0, 0);
        $time_hash = $date->getTimestamp();

        $message = 'decrypt' . $time_hash . $username;
        $enc_key = $time_hash . $pool_id;

        $decrypt_hash = base64_encode(hash_hmac('sha256', $message, $enc_key, true));
        return strtr($decrypt_hash, '+/', '-_');
    }
}
