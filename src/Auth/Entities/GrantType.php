<?php

namespace GestionKronos\Oauth\Auth\Entities;

enum GrantType: string
{
    case API = 'API';
    case PERSONAL = 'PERSONAL';
}