<?php
declare (strict_types=1);

namespace Wybwsk\JwtToken\Exception;


use RuntimeException;

class JwtTokenException extends RuntimeException {
    protected string|array $error;

    public function __construct($error, $code = 401) {
        parent::__construct();
        $this->error = $error;
        $this->code = $code;
        $this->message = is_array($error) ? implode(PHP_EOL, $error) : $error;
    }
}