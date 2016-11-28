<?php 

/*
 * crypt class for php
 *
 * @author fangjinmin@gmail.com
 * @date 2016/11/28
 * @version 1.0
 */


 class Crypt {

    const CIPHER = MCRYPT_RIJNDAEL_128;
    const MODE = MCRYPT_MODE_CBC;
    const ALGO = 'sha256';
    private $secretKey=null;
    private $ivSize=null;

 
    /*
     * construct method
     *
     * @param $key String secret key
     *
     */
    public function __construct($key) {
        $this->secretKey = $key;
        $this->ivSize = mcrypt_get_iv_size(self::CIPHER, self::MODE);
    }

    /*
     * encrypt data
     *
     * @param $data String the data to be encrypted
     * @return base64 endcoded encrypted data
     *
     */
    public function encrypt($data) {
        $blockSize = mcrypt_get_block_size(self::CIPHER,self::MODE);
        $data = $this->pkcs5_pad($data, $blockSize);
        $iv = mcrypt_create_iv($this->ivSize, MCRYPT_DEV_URANDOM);
        $cipherText = mcrypt_encrypt(self::CIPHER, $this->secretKey, $data, self::MODE, $iv);
        $hmac = hash_hmac(self::ALGO, $iv.$cipherText, $this->secretKey, false);
        return $this->base64Encode($hmac . $iv . $cipherText);
    }
    
    /*
     * decrypt data
     *
     * @param $data String the data to be decrypted
     * @return decrypted data. if falied i will be returned false.
     *
     */
    public function decrypt($data) {
        $data = $this->base64Decode($data);
        $hmac = substr($data, 0, 64);
        $iv = substr($data, 64, $this->ivSize);
        $cipherText = substr($data, 64 + $this->ivSize);
        $calculated = hash_hmac(self::ALGO, $iv.$cipherText, $this->secretKey, false);
        if (!hash_equals($hmac, $calculated)) {    
            return false;
        } else {
            $plainText = mcrypt_decrypt(self::CIPHER, $this->secretKey, $cipherText, self::MODE, $iv);
            $plainText = $this->pkcs5_unpad($plainText);
            return $plainText;
        }
    }

    /*
     * PKCS5Padding
     *
     * copied from http://php.net/manual/ja/ref.mcrypt.php#69782
     *
     */
    protected function pkcs5_pad($text, $blocksize){
        $pad = $blocksize - (strlen($text) % $blocksize);
        return $text . str_repeat(chr($pad), $pad);
    }

    /*
     * PKCS5UnPadding
     *
     * copied from http://php.net/manual/ja/ref.mcrypt.php#69782
     *
     */
    protected function pkcs5_unpad($text){
        $pad = ord($text{strlen($text)-1});
        if ($pad > strlen($text)) return false;
        if (strspn($text, chr($pad), strlen($text) - $pad) != $pad) return false;
        return substr($text, 0, -1 * $pad);
    }

    /*
     * URL safe base64 encode
     *
     * copied from http://php.net/manual/ja/function.base64-encode.php#103849
     *
     */
    protected function base64Encode($str) {
        return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
    }

    /*
     * URL safe base64 decode
     *
     * copied from http://php.net/manual/ja/function.base64-encode.php#103849
     *
     */
    private function base64Decode($str) {
        return base64_decode(str_pad(strtr($str, '-_', '+/'), strlen($str) % 4, '=', STR_PAD_RIGHT));
    }

    /*
     * destruct method
     *
     */
    public function __destruct() {
        unset($this->secretKey);
        unset($this->ivSize);
    }
 }

