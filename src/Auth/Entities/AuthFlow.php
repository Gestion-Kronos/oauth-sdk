<?php

namespace GestionKronos\Oauth\Auth\Entities;

enum AuthFlow: string
{
    case AUTH_CHALLENGE = 'AUTH_CHALLENGE';
    case USER_PASSWORD = 'USER_PASSWORD';
    case REFRESH = 'REFRESH';
}