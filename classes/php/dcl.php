<?php
/*
DCL  => One-way encryption with key and Alpha . 
Repo => https://github.com/AminCoder/DCL

How to use:
$key = "mykey12345";
$alpha = 6;
$plaintext = "userdata12345";
$dclInstance = new DCL($key, $alpha);
$result = $dclInstance->generate($plaintext);
echo $result . PHP_EOL;
*/

class DCL
{
    const MAX_A_RATIO = 999999;
    const HASH_LEN = 96;
    const CHAR_LIST_CODE1 = ["A", "B", "C", "D", "E", "F", "Z", "X", "Y", "S"];
    const CHAR_LIST_CODE2 = ["Q", "W", "R", "V", "M", "O", "N", "P", "L", "="];
    const CHAR_LIST_CODE3 = ["K", "H", "R", "Q", "T", "U", "I", "J", "G", "-"];
    const CHAR_LIST_CODE4 = ["a", "*", "q", "!", "@", "p", "u", "i", "?", "/"];
    const CHAR_LIST_CODE5 = ["b", "$", "s", "#", "&", "k", "u", "t", "+", ")"];
    private $key;
    private $alpha;
    private $num_list_code;
    private $plaintext;
    private $key_ascii_code;
    private $plaintext_ascii_code;
    private $sum_all_plaintext_chr;
    private $sum_all_key_chr;

    public function __construct($key, $alpha)
    {
        $this->key = $key;
        $this->alpha = $alpha;
        $this->num_list_code = range(0, 9);
        $this->plaintext = "";
        $this->key_ascii_code = [];
        $this->plaintext_ascii_code = [];
        $this->sum_all_plaintext_chr = 0;
        $this->sum_all_key_chr = 0;
    }

    private function checkAlphaValidation() 
    {
        if ($this->alpha != 0) {
            return;
        }
        $keyascci = ord($this->key[0]);
        $this->alpha = (int) substr(strval($keyascci), -1);
        if ($this->alpha == 0) {
            $this->alpha = 5;
        }
    }
    
    private function checkInputs()
    {
        if ($this->alpha > 9 || $this->alpha < 0) {
            throw new Exception("Alpha must be set between 0 and 9.");
        }
        if (empty($this->key)) {
            throw new Exception("The key cannot be considered empty.");
        } elseif (strlen($this->key) > 32) {
            throw new Exception("The maximum allowed key is 32 characters.");
        } elseif ($this->plaintext == NULL) {
            throw new Exception("The plaintext cannot be empty.");
        }
        $this->checkAlphaValidation();
    }

    public function generate($plaintext)
    {
        $this->plaintext = $plaintext;
        $this->checkInputs();
        $this->plaintext_ascii_code = $this->getAsciiCode($this->plaintext, 0);
        $this->key_ascii_code = $this->getAsciiCode($this->key, 1);
        $mergeCodes = $this->mergeKeyAndPlaintext();
        $alphaProcList = $this->alphaEnSet($mergeCodes);
        $compressAlphaProc = $this->compressAProcess($alphaProcList);
        $cipherOut = "";
        if (strlen($compressAlphaProc) >= self::HASH_LEN) {
            $cipherOut = $this->cipherCompression($compressAlphaProc);
        } else {
            $cipherOut = $this->cipherExpansion($compressAlphaProc);
        }

        $cipherOut = $this->cipherCharacterization($cipherOut);
        return $cipherOut;
    }

    private function getAsciiCode($value, $stateAsc)
    {
        if ($value == NULL) {
            return null;
        }

        $result = [];
        $sumAsc = 0;
        
        $valueLength = mb_strlen($value, "UTF-8");
        for ($index = 0; $index < $valueLength; $index++) {
            $char = mb_substr($value, $index, 1, "UTF-8");
            $result[] = mb_ord($char, "UTF-8");
            $sumAsc += ($index + 1) * $result[$index];
        }

        if ($stateAsc == 0) {
            $this->sum_all_plaintext_chr = $sumAsc;
        } elseif ($stateAsc == 1) {
            $this->sum_all_key_chr = $sumAsc;
        }

        return $result;
    }

    private function mergeKeyAndPlaintext()
    {
        $result = [];

        for ($indexMain = 0; $indexMain < count($this->plaintext_ascii_code); $indexMain++) {
            $mergesum = 0;

            for ($indexSub = 0; $indexSub < count($this->key_ascii_code); $indexSub++) {
                $mergesum += round(($this->plaintext_ascii_code[$indexMain] * ($indexMain + 1)) + ($this->key_ascii_code[$indexSub] * ($indexSub + 1)),0, $mode = PHP_ROUND_HALF_EVEN);
            }

            $result[] = $mergesum;
        }

        return $result;
    }

    private function alphaEnSet($mergeCodes)
    {
        $result = [];
        $aratio = 0;

        for ($index = 0; $index < count($mergeCodes); $index++) {
            $aproc = ($mergeCodes[$index] * $this->alpha) + $aratio;
            $result[] = $aproc;
            $aratio = $this->createNewAratio($index, $aproc, $aratio);
        }

        return $result;
    }

    private function createNewAratio($index, $aproc, &$a)
    {
        try {
            if ($a > self::MAX_A_RATIO) {
                $a = (strlen($this->plaintext) * $this->alpha * $index);
                return round($a);
            }

            if ($aproc % 2 != 0) {
                $a = round(($aproc / $this->plaintext_ascii_code[$index]) * strlen($this->plaintext),0, $mode = PHP_ROUND_HALF_EVEN);
            } else {
                $a = round(($aproc / $this->plaintext_ascii_code[$index]) * (strlen($this->plaintext) * ($index + 1) + $this->plaintext_ascii_code[$index]),0, $mode = PHP_ROUND_HALF_EVEN);
            }
        } catch (Exception $ex) {
            $a = (strlen($this->plaintext) * $this->alpha * $index);
        }

        return round($a);
    }

    private function compressAProcess($aprocList)
    {
        $result = "";
        $compressResult = 0;
        $lastResult = 1000;

        for ($index = 0; $index < count($aprocList); $index++) {
            $sumAscii = 0;
            $aprocStr = strval($aprocList[$index]);

            for ($charIndex = 0; $charIndex < strlen($aprocStr); $charIndex++) {
                $sumAscii += intval($aprocStr[$charIndex]);
            }

            $compressResult = round($sumAscii * intval($aprocStr[strlen($aprocStr) - 1]) * (($index + 1) * $this->alpha) + ($this->plaintext_ascii_code[$index] * (($index + 1) * strlen($aprocStr))) ,0, $mode = PHP_ROUND_HALF_EVEN );
            $compressResult += $this->createNewKratio($index, $lastResult);
            $compressResult += $this->sum_all_plaintext_chr + $this->sum_all_key_chr;
            $result .= strval($compressResult);
            $lastResult = $compressResult;
        }

        return $result;
    }

    private function createNewKratio($index, $lastResult)
    {
        $index += 1;
        $k = 0;
        $blast = intval(strval($lastResult)[-1]);

        if ($blast % 2 != 0) {
            $k = round(($lastResult / $index) + $this->alpha ,0, $mode = PHP_ROUND_HALF_EVEN);
        } else {
            $k = round(($lastResult / $index) + ($this->alpha * 3) ,0, $mode = PHP_ROUND_HALF_EVEN);
        }

        if ($k > 2147483647) {
            $k = round(($lastResult / ($index * $this->alpha * 3)),0, $mode = PHP_ROUND_HALF_EVEN);
        }

        if (count($this->plaintext_ascii_code) > 32) {
            $k = $k + (count($this->plaintext_ascii_code) * $this->alpha);
        } else {
            $k = count($this->plaintext_ascii_code) * $k ;
        }

        if ($k <= 0) {
            $k = $index * $this->alpha ;
        }
        return $k;
    }

    private function cipherCompression($aproc)
    {
        $i = 1;

        while (self::HASH_LEN < strlen($aproc)) {
            if ($i >= strlen($aproc)) {
                $i = 1;
            }

            $leftDigit = intval($aproc[$i - 1]);
            $rightDigit = intval($aproc[strlen($aproc) - $i]);
            $_sum = $leftDigit + $rightDigit;

            if ($_sum >= 10) {
                $aproc = substr($aproc, 1);

                if (strlen($aproc) == self::HASH_LEN) {
                    return $aproc;
                }

                $aproc = substr($aproc, 0, strlen($aproc) - $i) . substr($aproc, strlen($aproc) - $i + 1);
                $i += 1;
                continue;
            }

            $aproc = substr($aproc, 1);

            if (strlen($aproc) == self::HASH_LEN) {
                return $aproc;
            }

            $aproc = substr($aproc, 0, strlen($aproc) - $i) . substr($aproc, strlen($aproc) - $i + 1);
            $aproc .= strval($_sum);
            $i += 1;
        }

        return $aproc;
    }

    private function cipherExpansion($aproc)
    {
        $i = 1;

        while (self::HASH_LEN > strlen($aproc)) {
            if ($i >= strlen($aproc)) {
                $i = 1;
            }

            $firstnum = intval($aproc[0]);
            $lastnum = intval($aproc[strlen($aproc) - 1]);
            $aproc = substr($aproc, 1, -1);

            if ($firstnum % 2 != 0) {
                $aproc .= strval(round(($firstnum * $this->alpha * $this->sum_all_key_chr) + ($i * $this->sum_all_plaintext_chr) + strlen($aproc)));
            } else {
                $aproc = strval(round(((($firstnum * $this->alpha * $this->sum_all_key_chr) + ($this->sum_all_plaintext_chr * $lastnum)) + strlen($aproc)))) . $aproc;
            }

            $i += 1;
        }

        if (strlen($aproc) > self::HASH_LEN) {
            $aproc = substr($aproc, 0, self::HASH_LEN);
        }

        return $aproc;
    }

    private function cipherCharacterization($cipher)
    {
        for ($index = 0; $index < 10; $index++) {
            $iPutten = $this->num_list_code[$index] - $this->alpha;

            if ($iPutten < 0) {
                $iPutten += 10;
            }

            $this->num_list_code[$index] = $iPutten;
        }
        $CHAR_LIST_CODE = self::select_char_list();
        for ($index = 0; $index < 10; $index++) {
            $cipher = str_replace(strval($this->num_list_code[$index]), $CHAR_LIST_CODE[$index], $cipher);
        }

        return $cipher;
    }

    private function select_char_list() {
    
        $cacode = intval(strval($this->sum_all_key_chr)[strlen(strval($this->sum_all_key_chr)) - 1]) +
        intval(strval($this->sum_all_plaintext_chr)[strlen(strval($this->sum_all_plaintext_chr)) - 1]) +
        $this->alpha;
    
        $result = intval(strval($cacode)[strlen(strval($cacode)) - 1]);
    
        if ($result == 0 || $result == 9) {
            return self::CHAR_LIST_CODE1;
        } elseif ($result == 1 || $result == 8) {
            return self::CHAR_LIST_CODE2;
        } elseif ($result == 2 || $result == 7) {
            return self::CHAR_LIST_CODE3;
        } elseif ($result == 3 || $result == 6) {
            return self::CHAR_LIST_CODE4;
        } else {
            return self::CHAR_LIST_CODE5;
        }
    }
}

?>
