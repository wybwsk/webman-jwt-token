<?php

return [
    'enable' => true,
    'stores' => [
        'default' => [
            'login_type'  => 'mpo', //  登录方式，sso为单点登录，mpo为多点登录
            'signer_key'  => 'abcabc',//加密密钥
            'public_key'  => base_path() . DIRECTORY_SEPARATOR . 'public.key',
            'private_key' => base_path() . DIRECTORY_SEPARATOR . 'private.key',
            'expires_at'  => 86400,
            'refresh_ttL' => 90000,
            'iss'         => 'api.test.com',
        ],
    ]
];