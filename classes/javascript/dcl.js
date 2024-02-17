/*
DCL  => One-way encryption with key and Alpha . 
Repo => https://github.com/AminCoder/DCL

How to use:
            const plaintext = document.getElementById('plaintext').value;
            const key = document.getElementById('key').value;
            const alpha = parseInt(document.getElementById('alpha').value);
            const dclInstance = new DCL(key, alpha);
            const ciphertext = dclInstance.generate(plaintext);
            document.getElementById('cipher').value = ciphertext;
*/

class DCL {
    constructor(key, alpha) {
        this.MAX_A_RATIO = 999999;
        this.hashlen = 96;
        this.alpha = alpha;
        this.key = key;
        this.plaintext = "";
        this.CHAR_LIST_CODE1 = ["A", "B", "C", "D", "E", "F", "Z", "X", "Y", "S"];
        this.CHAR_LIST_CODE2 = ["Q", "W", "R", "V", "M", "O", "N", "P", "L", "="];
        this.CHAR_LIST_CODE3 = ["K", "H", "R", "Q", "T", "U", "I", "J", "G", "-"];
        this.CHAR_LIST_CODE4 = ["a", "*", "q", "!", "@", "p", "u", "i", "?", "/"];
        this.CHAR_LIST_CODE5 = ["b", "$", "s", "#", "&", "k", "u", "t", "+", ")"];
        this.numListCode = [...Array(10).keys()];
        this.plaintextasciicode = [];
        this.keyasciicode = [];
        this.sumAllPlaintextChr = 0;
        this.sumAllKeyChr = 0;
    }

    checkInputs() {
        if (this.alpha > 9) {
            throw new Error("Alpha must be set between 0 and 9.");
        }
        if (this.key === "") {
            throw new Error("The key cannot be considered empty.");
        } else if (this.key.length > 32) {
            throw new Error("The maximum allowed key is 32 characters.");
        } else if (this.plaintext.length === 0) {
            throw new Error("The plaintext cannot be empty.");
        }
    }

    generate(plaintext) {
        this.plaintext = plaintext;
        this.checkInputs();
        this.plaintextasciicode = this.getAsciiCode(this.plaintext,0);
        this.keyasciicode = this.getAsciiCode(this.key,1);
        let mergecodes = this.mergeKeyAndPlaintext();   
        let aproclist = this.alphaEnSet(mergecodes);
        let comoressaproc = this.compressAprocess(aproclist);
        let cipherout = "";
        if (comoressaproc.length >= this.hashlen) {
            cipherout = this.cipherCompression(comoressaproc);
        } else {
            cipherout = this.cipherExpansion(comoressaproc);
        }
        cipherout = this.cipherCharacterization(cipherout);
        return cipherout;
    }

    getAsciiCode(value, state_asc) {
        if (value === '') return null;
        let sumasc = 0 ;
        let flength = value.length - 1;
        let result = new Int32Array(flength + 1);
        for (let index = 0; index <= flength; index++) {
            result[index] = value.charCodeAt(index);
            sumasc += (index + 1) * result[index];
        }
        if(state_asc == 0)
        {
            this.sumAllPlaintextChr = sumasc;
        }else if(state_asc == 1)
        {
            this.sumAllKeyChr = sumasc;
        }
        return result;
    }

    print(v) {
        console.log(v.join(' '));
    }

    mergeKeyAndPlaintext() {
        return this.plaintextasciicode.map((ascchar, imain) => {
            let mergesum = 0;
            this.keyasciicode.forEach((keyasc, isub) => {
                mergesum += (ascchar * (imain + 1)) + (keyasc * (isub + 1));
            });
            return mergesum;
        });
    }

    alphaEnSet(mergecodes) {
        let aratio = 0;
        return mergecodes.map((mergecode, index) => {
            let aproc = (mergecode * this.alpha) + aratio;
            aratio = this.createNewAratio(index, aproc,aratio);
            return aproc;
        });
    }

    createNewAratio(index, aproc,a) {
        try {
            if (a > this.MAX_A_RATIO) {
                a = (this.plaintext.length * this.alpha * index);
                return a;
            }
            if (aproc % 2 !== 0) {
                a = this.roundToEven((aproc / this.plaintextasciicode[index]) * this.plaintext.length);
                return a;
            } else {
                a = this.roundToEven((aproc / this.plaintextasciicode[index]) * (this.plaintext.length * (index + 1) + this.plaintextasciicode[index]));
                return a;
            }
        } catch (ex) {
            a = (this.plaintext.length * this.alpha * index);
        }
        return a;
    }

    compressAprocess(aproc) {
        let compressmergeresult = "";
        let lastresult = 1000;
        aproc.forEach((aprocval, index) => {
            let sumascii = [...aprocval.toString()].reduce((acc, char) => acc + parseInt(char), 0);
            let compressresult = 0;
            compressresult = this.roundToEven((sumascii * parseInt(aprocval.toString()[aprocval.toString().length - 1]) * ((index + 1) * this.alpha) + (this.plaintextasciicode[index] * ((index + 1) * aprocval.toString().length))));
            compressresult += this.roundToEven(this.createNewKratio(index, lastresult));
            compressresult += this.sumAllPlaintextChr + this.sumAllKeyChr;
            compressmergeresult += compressresult.toString();
            lastresult = compressresult;
        });
        return compressmergeresult;
    }

    createNewKratio(index, lastresult) {
        index += 1;
        let k = 0;
        let blast = parseInt(lastresult.toString()[lastresult.toString().length - 1]);
        if (blast % 2 !== 0) {
            k = this.roundToEven((lastresult / index) + this.alpha);
        } else {
            k = this.roundToEven((lastresult / index) + (this.alpha * 3));
        }

        if (k > 2147483647) {
            k = this.roundToEven((lastresult / (index * this.alpha * 3)));
        }

        if (this.plaintextasciicode.length > 32) {
            k += this.roundToEven(this.alpha * this.plaintextasciicode.length);
        } else {
            k *= this.roundToEven(this.plaintextasciicode.length);
        }

        if (k <= 0) {
            k = this.roundToEven(index * this.alpha);
        }
        return k;
    }

    cipherCompression1(aproc) {
        let i = 1;
        while (this.hashlen < aproc.length) {
            if (i >= aproc.length) {
                i = 1;
            }
            let leftdigit = parseInt(aproc[i - 1]);
            let rightdigit = parseInt(aproc[aproc.length - i]);
            let sum = leftdigit + rightdigit;
            console.log(aproc);
            console.log(leftdigit + " " + rightdigit + " = " + sum);
            if (sum >= 10) {
                aproc = aproc.slice(1);
                if (aproc.length == this.hashlen) {
                    return aproc;
                }
                aproc = aproc.slice(0, -i);
                i += 1;
                continue;
            }
            
            aproc = aproc.slice(1);
            if (aproc.length == this.hashlen) {
                return aproc;
            }
            aproc = aproc.slice(0, -i);
            aproc += sum.toString();
            i += 1;
        }
        return aproc;
    }

    cipherCompression2(aproc) {
        let i = 1;
        while (this.hashlen < aproc.length) {
            console.log(aproc);
            if (i >= aproc.length) {
                i = 1;
            }
            let leftdigit = parseInt(aproc[i - 1]);
            let rightdigit = parseInt(aproc[aproc.length - i]);
            let sum = leftdigit + rightdigit;
            if (sum >= 10) {
                aproc = aproc.substring(1);
                if (aproc.length === this.hashlen) {
                    return aproc;
                }
                aproc = aproc.substring(0, aproc.length - i);
                i += 1;
                continue;
            }
            //console.log(sum + " " + aproc);
            //console.ReadLine();
            aproc = aproc.substring(1);
            if (aproc.length === this.hashlen) {
                return aproc;
            }
            aproc = aproc.substring(0, aproc.length - i);
            aproc += sum.toString();
            i += 1;
        }
    
        return aproc;
    }
    
    cipherCompression(aproc) {
        let i = 1;
        while (this.hashlen < aproc.length) {
            if (i >= aproc.length) {
                i = 1;
            }
            let leftDigit = parseInt(aproc[i - 1]);
            let rightDigit = parseInt(aproc[aproc.length - i]);
            let sum = leftDigit + rightDigit;
    
            if (sum >= 10) {
                aproc = aproc.substring(1);
                if (aproc.length === this.hashlen) {
                    return aproc;
                }
                aproc = aproc.substring(0, aproc.length - i) + aproc.substring(aproc.length - i + 1);
                i++;
                continue;
            }
    
            aproc = aproc.substring(1);
            if (aproc.length === this.hashlen) {
                return aproc;
            }
            aproc = aproc.substring(0, aproc.length - i) + aproc.substring(aproc.length - i + 1);
            aproc += sum.toString();
            i++;
        }
        return aproc;
    }

    
    cipherExpansion(aproc) {
        let i = 1;
        while (this.hashlen > aproc.length) {
            if (i >= aproc.length) {
                i = 1;
            }
            let firstnum = parseInt(aproc[0]);
            let lastnum = parseInt(aproc[aproc.length - 1]);
            aproc = aproc.slice(1);
            aproc = aproc.slice(0, aproc.length - 1);
            if (firstnum % 2 !== 0) {
                aproc += ((firstnum * this.alpha) * this.sumAllKeyChr) + (i * this.sumAllPlaintextChr) + aproc.length;
            } else {
                aproc = (((firstnum * this.alpha) * this.sumAllKeyChr) + (this.sumAllPlaintextChr * lastnum)) + aproc.length + aproc;
            }
            
            i += 1;
        }
        if (aproc.length > this.hashlen) {
            aproc = aproc.slice(0, this.hashlen);
        }
        return aproc;
    }

    cipherCharacterization(cipher) {
        for (let index = 0; index < 10; index++) {
            let iPutten = this.numListCode[index] - this.alpha;
            if (iPutten < 0) {
                iPutten += 10;
            }
            this.numListCode[index] = iPutten;
        }
    
        const charListCode = this.selectCharList();
        for (let index = 0; index < 10; index++) {
            const regex = new RegExp(this.numListCode[index].toString(), 'g');
            cipher = cipher.replace(regex, charListCode[index]);
        }
    
        return cipher;
    }

    selectCharList() {
        const cacode = parseInt(this.sumAllKeyChr.toString().slice(-1)) +
                        parseInt(this.sumAllPlaintextChr.toString().slice(-1)) +
                        this.alpha;
        const result = parseInt(cacode.toString().slice(-1));
    
        if (result === 0 || result === 9) {
            return this.CHAR_LIST_CODE1;
        } else if (result === 1 || result === 8) {
            return this.CHAR_LIST_CODE2;
        } else if (result === 2 || result === 7) {
            return this.CHAR_LIST_CODE3;
        } else if (result === 3 || result === 6) {
            return this.CHAR_LIST_CODE4;
        } else {
            return this.CHAR_LIST_CODE5;
        }
    }
    

    roundToEven(number) {
        const roundedNumber = Math.round(number);
        if (roundedNumber % 2 === 0) {
            return roundedNumber;
        } else if (Math.abs(number - roundedNumber) === 0.5) {
            return Math.floor(number / 2) * 2;
        } else {
            return roundedNumber;
        }
    }

}
