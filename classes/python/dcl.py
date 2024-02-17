""" 
DCL  => One-way encryption with key and Alpha . 
Repo => https://github.com/AminCoder/DCL

How to use:
    key = "mykey12345"
    alpha = 6
    plaintext = input("> ")
    dcl_instance = DCL(key, alpha)
    result = dcl_instance.generate(plaintext)
    print(result)
"""

class DCL:
    MAX_A_RATIO = 999999
    HASH_LEN = 96
    CHAR_LIST_CODE1 = ["A", "B", "C", "D", "E", "F", "Z", "X", "Y", "S"]
    CHAR_LIST_CODE2 = ["Q", "W", "R", "V", "M", "O", "N", "P", "L", "="]
    CHAR_LIST_CODE3 = ["K", "H", "R", "Q", "T", "U", "I", "J", "G", "-"]
    CHAR_LIST_CODE4 = ["a", "*", "q", "!", "@", "p", "u", "i", "?", "/"]
    CHAR_LIST_CODE5 = ["b", "$", "s", "#", "&", "k", "u", "t", "+", ")"]

    def __init__(self, key, alpha):
        self.key = key
        self.alpha = alpha
        self.num_list_code = list(range(10))
        self.plaintext = ""
        self.key_ascii_code = []
        self.plaintext_ascii_code = []
        self.sum_all_plaintext_chr = 0
        self.sum_all_key_chr = 0

    def check_alpha_validation(self):
        if self.alpha != 0:
            return
        keyascci = ord(self.key[0])
        self.alpha = int(str(keyascci)[len(str(keyascci)) - 1])
        if self.alpha == 0:
            self.alpha = 5


    def check_inputs(self):
        if self.alpha > 9 or self.alpha < 0:
            raise Exception("Alpha must be set between 0 and 9.")
        if not self.key:
            raise Exception("The key cannot be considered empty.")
        elif len(self.key) > 32:
            raise Exception("The maximum allowed key is 32 characters.")
        elif len(self.plaintext) == 0:
            raise Exception("The plaintext cannot be empty.")
        self.check_alpha_validation()

    def generate(self, plaintext):
        self.plaintext = plaintext
        self.check_inputs()
        self.plaintext_ascii_code = self.get_ascii_code(self.plaintext, 0)
        self.key_ascii_code = self.get_ascii_code(self.key, 1)
        merge_codes = self.merge_key_and_plaintext()
        alpha_proc_list = self.alpha_en_set(merge_codes)
        compress_alpha_proc = self.compress_aprocess(alpha_proc_list)
        cipher_out = ""

        if len(compress_alpha_proc) >= self.HASH_LEN:
            cipher_out = self.cipher_compression(compress_alpha_proc)
        else:
            cipher_out = self.cipher_expansion(compress_alpha_proc)

        cipher_out = self.cipher_characterization(cipher_out)
        return cipher_out

    def get_ascii_code(self, value, state_asc):
        if not value:
            return None
        result = [ord(char) for char in value]
        sum_asc = 0
        for index, char_ascii in enumerate(result):
            sum_asc += (index + 1) * char_ascii
        
        if(state_asc == 0) :
            self.sum_all_plaintext_chr = sum_asc
        elif(state_asc == 1):
            self.sum_all_key_chr = sum_asc
            
        return result

    def merge_key_and_plaintext(self):
        result = []
        for index_main, char_ascii in enumerate(self.plaintext_ascii_code):
            mergesum = 0
            for index_sub, key_ascii in enumerate(self.key_ascii_code):
                mergesum += (char_ascii * (index_main + 1)) + (key_ascii * (index_sub + 1))
            result.append(mergesum)
        return result

    def alpha_en_set(self, merge_codes):
        result = []
        aratio = 0
        for index, merge_code in enumerate(merge_codes):
            aproc = (merge_code * self.alpha) + aratio
            result.append(aproc)
            aratio = self.create_new_aratio(index, aproc , aratio)
        return result

    def create_new_aratio(self, index, aproc , a):
        try:
            if a > self.MAX_A_RATIO:
                a = (len(self.plaintext) * self.alpha * index)
                return round(a)
            if aproc % 2 != 0:
                a = (aproc / self.plaintext_ascii_code[index]) * len(self.plaintext)
            else:
                a = (aproc / self.plaintext_ascii_code[index]) * (len(self.plaintext) * (index + 1) + self.plaintext_ascii_code[index])
        except Exception as ex:
            a = (len(self.plaintext) * self.alpha * index)
        return round(a)

    def compress_aprocess(self, aproc_list):
        result = ""
        compress_result = 0
        last_result = 1000

        for index, aproc in enumerate(aproc_list):
            sum_ascii = 0
            aproc_str = str(aproc)
            for char in aproc_str:
                sum_ascii += int(char)
            compress_result = round(sum_ascii * int(aproc_str[-1]) * ((index + 1) * self.alpha) + (self.plaintext_ascii_code[index] * ((index + 1) * len(aproc_str))))
            compress_result += round(self.create_new_kratio(index, last_result))
            compress_result += round(self.sum_all_plaintext_chr + self.sum_all_key_chr)
            result += str(compress_result)
            last_result = compress_result
        return result

    def create_new_kratio(self, index, last_result):
        index += 1
        k = 0
        blast = int(str(last_result)[-1])

        if blast % 2 != 0:
            k = round((last_result / index) + self.alpha)
        else:
            k = round((last_result / index) + (self.alpha * 3))
        
        if k > 2147483647:
              k = round((last_result/ (index * self.alpha * 3)))

        if len(self.plaintext_ascii_code) > 32:
            k = k + (len(self.plaintext_ascii_code) * self.alpha)
        else:
            k = len(self.plaintext_ascii_code) * k 

        

        if k <= 0:
            k = index * self.alpha
        
        return k

    def cipher_compression(self, aproc):
        i = 1
        while self.HASH_LEN < len(aproc):
            if i >= len(aproc):
                i = 1
            left_digit = int(aproc[i - 1])
            right_digit = int(aproc[len(aproc) - i ])
            _sum = left_digit + right_digit
            if _sum >= 10:
                aproc = aproc[1:]
                if len(aproc) == self.HASH_LEN:
                    return aproc
                aproc = aproc[:len(aproc)-i] + aproc[len(aproc)-i+1:]
                i += 1
                continue
            aproc = aproc[1:]
            if len(aproc) == self.HASH_LEN:
                return aproc
            aproc = aproc[:len(aproc)-i] + aproc[len(aproc)-i+1:]

            aproc += str(_sum)
            i += 1
        return aproc



    def cipher_expansion(self, aproc):
        i = 1
        
        while self.HASH_LEN > len(aproc):
            if i >= len(aproc):
                i = 1
            firstnum = int(aproc[0])
            lastnum = int(aproc[-1])
            aproc = aproc[1:-1]
            if firstnum % 2 != 0:
                aproc += str(round((firstnum * self.alpha * self.sum_all_key_chr) + (i * self.sum_all_plaintext_chr) + len(aproc)))
            else:
                aproc = str(round(((firstnum * self.alpha * self.sum_all_key_chr) + (self.sum_all_plaintext_chr * lastnum)) + len(aproc))) + aproc
            i += 1

        if len(aproc) > self.HASH_LEN:
            aproc = aproc[:self.HASH_LEN]

        return aproc



    def cipher_characterization(self, cipher):
        for index in range(10):
            i_putten = self.num_list_code[index] - self.alpha
            if i_putten < 0:
                i_putten += 10
            self.num_list_code[index] = i_putten

        char_list_code = self.select_char_list()
        for index in range(10):
            cipher = cipher.replace(str(self.num_list_code[index]), char_list_code[index])
        return cipher
    


    def select_char_list(self):
        cacode = int(str(self.sum_all_key_chr)[-1]) + int(str(self.sum_all_plaintext_chr)[-1]) + self.alpha
        result = int(str(cacode)[-1])
        if result == 0 or result == 9:
            return self.CHAR_LIST_CODE1
        elif result == 1 or result == 8:
            return self.CHAR_LIST_CODE2
        elif result == 2 or result == 7:
            return self.CHAR_LIST_CODE3
        elif result == 3 or result == 6:
            return self.CHAR_LIST_CODE4
        else:
            return self.CHAR_LIST_CODE5


