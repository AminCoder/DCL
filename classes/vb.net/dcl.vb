Imports System.Runtime.InteropServices
Imports System.Runtime.InteropServices.JavaScript.JSType
Imports System.Text
Imports System.Text.Unicode

Public Class dcl
    Private Const MAX_A_RATIO As Integer = 999999
    Private Const hashlen As Integer = 96
    Private alpha As Byte, key, plaintext As String
    Private charlistcode1() As Char = {"A", "B", "C", "D", "E", "F", "Z", "X", "Y", "S"}
    Private charlistcode2() As Char = {"Q", "W", "R", "V", "M", "O", "N", "P", "L", "="}
    Private charlistcode3() As Char = {"K", "H", "R", "Q", "T", "U", "I", "J", "G", "-"}
    Private charlistcode4() As Char = {"a", "*", "q", "!", "@", "p", "u", "i", "?", "/"}
    Private charlistcode5() As Char = {"b", "$", "s", "#", "&", "k", "u", "t", "+", ")"}
    Private numlistcode(9) As Byte
    Private plaintextasciicode(), keyasciicode() As Integer
    Private sumallplaintextchr, sumallkeychr As Long
    Public Sub New(key As String, alpha As Byte)
        Me.key = key
        Me.alpha = alpha
        For index = 0 To 9
            numlistcode(index) = index
        Next
    End Sub

    Private Sub check_alpha_validation()
        If alpha <> 0 Then Return
        Dim keyascci As Integer = AscW(key(0))
        alpha = CInt(keyascci.ToString()(keyascci.ToString.Length - 1).ToString)
        If alpha = 0 Then alpha = 5
    End Sub

    Private Sub check_inputs()
        If alpha > 9 Then
            Throw New Exception("Alpha must be set between 0 and 9.")
        End If
        If key = String.Empty Then
            Throw New Exception("The key cannot be considered empty.")
        ElseIf key.Length > 32 Then
            Throw New Exception("The maximum allowed key is 32 characters.")
        ElseIf plaintext.Length = 0 Then
            Throw New Exception("The plaintext cannot be empty.")
        End If
        check_alpha_validation()
    End Sub

    Public Function generate(plaintext As String)
        Me.plaintext = plaintext
        check_inputs()
        plaintextasciicode = get_ascii_code(plaintext, sumallplaintextchr)
        keyasciicode = get_ascii_code(key, sumallkeychr)
        Dim mergecodes = merge_key_and_plaintext()
        Dim aproclist = alpha_en_set(mergecodes)
        Dim comoressaproc = compress_aprocess(aproclist)
        Dim cipherout As String = String.Empty
        If comoressaproc.Length >= hashlen Then
            cipherout = cipher_compression(comoressaproc)
        Else
            cipherout = cipher_expansion(comoressaproc)
        End If
        cipher_characterization(cipherout)
        Return cipherout
    End Function

    Private Function get_ascii_code(value As String, ByRef sumasc As Long) As Integer()
        If value = String.Empty Then Return Nothing
        Dim flength As Integer = value.Length - 1
        Dim result(flength) As Integer
        For index = 0 To flength
            result(index) = AscW(value(index))
            sumasc += ((index + 1) * result(index))
        Next
        Return result
    End Function

    Private Sub print(v() As Long)
        For index = 0 To v.Length - 1
            Console.Write(v(index).ToString & " ")
        Next
    End Sub

    Private Function merge_key_and_plaintext() As Long()
        Dim fmainlength As Integer = plaintext.Length - 1
        Dim fkeylength As Integer = key.Length - 1
        Dim result(fmainlength) As Long
        Dim mergesum As Long = 0
        For imain = 0 To fmainlength
            Dim ascchar As Integer = plaintextasciicode(imain)
            For isub = 0 To fkeylength
                mergesum += (ascchar * (imain + 1)) + (keyasciicode(isub) * (isub + 1))
            Next
            result(imain) = mergesum
            mergesum = 0
        Next
        Return result
    End Function

    Private Function alpha_en_set(mergecodes() As Long) As Long()
        Dim fmainlength As Integer = plaintext.Length - 1
        Dim result(fmainlength) As Long
        Dim aratio As Long = 0
        For index = 0 To fmainlength
            Dim aproc As Long = (mergecodes(index) * alpha) + aratio
            result(index) = aproc
            create_new_aratio(index, aproc, aratio)
        Next
        Return result
    End Function

    Private Function create_new_aratio(index As Integer, aproc As Long, ByRef a As Long) As Boolean
        Try
            If a > MAX_A_RATIO Then
                a = (plaintext.Length * alpha * index)
                Return True
            End If
            If aproc Mod 2 <> 0 Then
                a = (aproc / plaintextasciicode(index)) * plaintext.Length
                Return True
            Else
                a = (aproc / plaintextasciicode(index)) * (plaintext.Length * (index + 1) + plaintextasciicode(index))
                Return False
            End If
        Catch ex As Exception
            a = (plaintext.Length * alpha * index)
        End Try
        Return True
    End Function

    Private Function compress_aprocess(aproc() As Long) As String
        Dim fmainlength As Integer = plaintext.Length - 1
        Dim result(fmainlength) As Long
        Dim compressresult As Long = 0
        Dim lastresult As Long = 1000
        Dim compressmergeresult As String = String.Empty
        For index = 0 To fmainlength
            Dim sumascii As Integer = 0
            Dim aprocstr = aproc(index).ToString
            For isub = 0 To aprocstr.Length - 1
                sumascii += CInt(aprocstr(isub).ToString)
            Next
            compressresult = (sumascii * CInt(aprocstr(aprocstr.Length - 1).ToString) * ((index + 1) * alpha) + (plaintextasciicode(index) * ((index + 1) * aprocstr.Length)))
            compressresult += create_new_kratio(index, lastresult)
            compressresult += sumallplaintextchr + sumallkeychr
            compressmergeresult &= compressresult.ToString
            lastresult = compressresult
        Next
        Return compressmergeresult
    End Function

    Private Function create_new_kratio(index As Integer, lastresult As Long) As Long
        index += 1
        Dim k As Long = 0
        Dim blast As Byte = CByte(lastresult.ToString()(lastresult.ToString.Length - 1).ToString)

        If blast Mod 2 <> 0 Then
            k = (lastresult / index) + alpha
        Else
            k = (lastresult / index) + (alpha * 3)
        End If

        If k > 2147483647 Then
            k = (lastresult / (index * alpha * 3))
        End If

        If plaintextasciicode.Length > 32 Then
            k += alpha * plaintextasciicode.Length
        Else
            k *= plaintextasciicode.Length
        End If

        If k <= 0 Then
            k = index * alpha
        End If

        Return k
    End Function

    Private Function cipher_compression(aproc As String) As String
        Dim i As Integer = 1
        While (hashlen < aproc.Length)
            If i >= aproc.Length Then
                i = 1
            End If
            Dim leftdigit As Integer = CInt(aproc(i - 1).ToString())
            Dim rightdigit As Integer = CInt(aproc(aproc.Length - i).ToString())
            Dim sum As Integer = leftdigit + rightdigit
            If sum >= 10 Then
                aproc = aproc.Remove(0, 1)
                If aproc.Length = hashlen Then
                    Return aproc
                End If
                aproc = aproc.Remove(aproc.Length - i, 1)
                i += 1
                Continue While
            End If
            aproc = aproc.Remove(0, 1)
            If aproc.Length = hashlen Then
                Return aproc
            End If
            aproc = aproc.Remove(aproc.Length - i, 1)
            aproc &= sum.ToString()
            i += 1
        End While

        Return aproc
    End Function

    Private Function cipher_expansion(aproc As String) As String
        Dim i As Integer = 1
        While (hashlen > aproc.Length)
            If i >= aproc.Length Then
                i = 1
            End If
            Dim firstnum As Byte = CByte(aproc(0).ToString)
            Dim lastnum As Byte = CByte(aproc(aproc.Length - 1).ToString)
            aproc = aproc.Remove(0, 1)
            aproc = aproc.Remove(aproc.Length - 1)

            If firstnum Mod 2 <> 0 Then
                aproc &= ((firstnum * alpha) * sumallkeychr) + (i * sumallplaintextchr) + aproc.Length
            Else
                aproc = (((firstnum * alpha) * sumallkeychr) + (sumallplaintextchr * lastnum)) + aproc.Length & aproc
            End If
            i += 1
        End While

        If aproc.Length > hashlen Then
            aproc = aproc.Remove(hashlen)
        End If
        Return aproc
    End Function

    Private Sub cipher_characterization(ByRef cipher As String)
        For index = 0 To 9
            Dim iputten As Integer = CInt(numlistcode(index)) - CInt(alpha)
            If iputten < 0 Then
                iputten += 10
            End If
            numlistcode(index) = iputten
        Next
        Dim charlistcode = select_char_list()
        For index = 0 To 9
            cipher = cipher.Replace(numlistcode(index).ToString, charlistcode(index).ToString)
        Next
    End Sub

    Private Function select_char_list() As Char()
        Dim cacode As Integer = CInt(sumallkeychr.ToString().Last().ToString) + CInt(sumallplaintextchr.ToString().Last().ToString) + alpha
        Dim result As Integer = CInt(cacode.ToString().Last().ToString)
        If result = 0 OrElse result = 9 Then
            Return charlistcode1
        ElseIf result = 1 OrElse result = 8 Then
            Return charlistcode2
        ElseIf result = 2 OrElse result = 7 Then
            Return charlistcode3
        ElseIf result = 3 OrElse result = 6 Then
            Return charlistcode4
        Else
            Return charlistcode5
        End If
    End Function
End Class
