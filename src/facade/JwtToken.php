<?php
declare (strict_types=1);

namespace Wybwsk\JwtToken\facade;
/**
 * @package Wybwsk\JwtToken\Facade
 * @see \Wybwsk\JwtToken\JwtToken
 * @mixin \Wybwsk\JwtToken\JwtToken
 * @method static token($id, array $claims) 生成 Token
 * @method static validate($token) 生成 Token
 */
class JwtToken {
    protected static array $_instance = [];

    public static function instance() {
        $app = \request()->app === '' ? 'default' : \request()->app;
        if (!isset(static::$_instance[$app])) {
            static::$_instance[$app] = new \Wybwsk\JwtToken\JwtToken($app);
        }
        return static::$_instance[$app];
    }

    /**
     * @param $name
     * @param $arguments
     * @return mixed
     */
    public static function __callStatic($name, $arguments) {
        return static::instance()->{$name}(... $arguments);
    }
}