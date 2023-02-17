<?php
declare (strict_types=1);

namespace Wybwsk\JwtToken;

use Carbon\Carbon;

use Exception;
use UnexpectedValueException;
use Wybwsk\JwtToken\Exception\JwtTokenException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use support\Redis;

class JwtToken {
    protected array  $jwtConfig = []; //JWT配置
    protected string $store;     //应用
    protected string $timeZone  = 'PRC'; //时区
    protected int    $iatTime; //JWT 发布时间

    public function __construct($store = null) {
        $_config = config('plugin.wybwsk.webman-jwt-token.app');
        if (empty($_config['stores'][$store])) {
            throw new JwtTokenException('The configuration file is abnormal or does not exist');
        } else {
            $this->store = $store;
        }
        foreach ($_config['stores'] as $key => $scene) {
            $this->jwtConfig[$key] = $scene;
        }
        $this->iatTime = Carbon::now($this->timeZone)->timestamp;
    }

    /**
     * 生成 Token
     */
    public function token($id, array $claims = []): array {
        $payload = $this->buildPayLoad($id, $claims);
        $token = $this->make($payload);
        if ($this->jwtConfig[$this->store]['login_type'] === 'sso') {
            Redis::setex($this->getCacheKey($id), $this->jwtConfig[$this->store]['expires_at'], $payload['iat']);
        }
        return $token;
    }

    public function validate($token) {
        $token = str_replace('Bearer ', '', $token);
        $jwtToken = $this->authcode($token, 'DECODE', $this->jwtConfig[$this->store]['signer_key']);
        if (!empty($jwtToken)) {
            try {
                $tokenPayload = (array)JWT::decode($jwtToken, new Key(file_get_contents($this->jwtConfig[$this->store]['public_key']), 'RS256'));
            } catch (SignatureInvalidException $e) {
                throw new JwtTokenException('身份验证令牌无效');
            } catch (BeforeValidException $e) { // 签名在某个时间点之后才能用
                throw new JwtTokenException('身份验证令牌尚未生效');
            } catch (ExpiredException $e) { // token过期
                throw new JwtTokenException('身份验证会话已过期，请重新登录！');
            } catch (UnexpectedValueException $unexpectedValueException) {
                throw new JwtTokenException('获取扩展字段不正确');
            } catch (Exception $e) {
                throw new JwtTokenException($e->getMessage());
            }
            $tokenPayload['data'] = (array)$tokenPayload['data'];
            if ($this->jwtConfig[$this->store]['login_type'] === 'sso') {
                //最新的TOKEN的发布时间
                $blackListIat = Redis::get($this->getCacheKey($tokenPayload['data']['uid']));
                if ($blackListIat != $tokenPayload['iat']) {
                    return false;
                }
            }
            return $tokenPayload;
        } else {
            return false;
        }
    }

    private function buildPayLoad($id, $claims): array {
        return [
            'iss'  => $this->jwtConfig[$this->store]['iss'],
            'aud'  => $this->store,
            'iat'  => $this->iatTime, //发布时间
            'nbf'  => $this->iatTime, //生效时间
            'exp'  => $this->getExpireTime($this->iatTime), //过期时间
            'jti'  => $this->getJti($id),
            'data' => $claims
        ];
    }

    private function make($payload): array {
        $refreshPayload = $payload;
        $refreshPayload['exp'] = $this->getRefreshExpireTime($this->iatTime);
        return [
            'token_type'     => 'Bearer',
            'access_token'   => $this->authcode(JWT::encode($payload, file_get_contents($this->jwtConfig[$this->store]['private_key']), 'RS256'), 'ENCODE', $this->jwtConfig[$this->store]['signer_key']),
            'expire'         => $this->getExpireTime($this->iatTime),
            'refresh_token'  => $this->authcode(JWT::encode($refreshPayload, file_get_contents($this->jwtConfig[$this->store]['private_key']), 'RS256'), 'ENCODE', $this->jwtConfig[$this->store]['signer_key']),
            'refresh_expire' => $this->getRefreshExpireTime($this->iatTime)
        ];
    }

    private function getRefreshExpireTime($iatTime) {
        return $iatTime + $this->jwtConfig[$this->store]['refresh_ttL'];
    }

    private function getExpireTime($iatTime) {
        return $iatTime + $this->jwtConfig[$this->store]['expires_at'];
    }

    private function getJti($id): string {
        return $this->store . "_token_" . $id;
    }

    private function getCacheKey($id) {
        return $this->store . 'BlackList:' . $this->getJti($id);
    }

    private function authcode($string, $operation = 'DECODE', $key = '', $expiry = 0): string {
        $ckey_length = 4;
        $key = md5($key);
        $keya = md5(substr($key, 0, 16));
        $keyb = md5(substr($key, 16, 16));
        $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length) : substr(md5(microtime()), -$ckey_length)) : '';
        $cryptkey = $keya . md5($keya . $keyc);
        $key_length = strlen($cryptkey);
        $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0) . substr(md5($string . $keyb), 0, 16) . $string;
        $string_length = strlen($string);
        $result = '';
        $box = range(0, 255);
        $rndkey = array();
        for ($i = 0; $i <= 255; $i++) {
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);
        }
        for ($j = $i = 0; $i < 256; $i++) {
            $j = ($j + $box[$i] + $rndkey[$i]) % 256;
            $tmp = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }
        for ($a = $j = $i = 0; $i < $string_length; $i++) {
            $a = ($a + 1) % 256;
            $j = ($j + $box[$a]) % 256;
            $tmp = $box[$a];
            $box[$a] = $box[$j];
            $box[$j] = $tmp;
            $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
        }
        if ($operation == 'DECODE') {
            if ((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26) . $keyb), 0, 16)) {
                return substr($result, 26);
            } else {
                return '';
            }
        } else {
            return $keyc . str_replace('=', '', base64_encode($result));
        }
    }
}