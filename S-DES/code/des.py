
IP = [2, 6, 3, 1, 4, 8, 5, 7]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
IP_INVERSE = [4, 1, 3, 5, 7, 2, 8, 6]
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
P4 = [2, 4, 3, 1]

S0 = [[1, 0, 3, 2],
      [3, 2, 1, 0],
      [0, 2, 1, 3],
      [3, 1, 3, 2]]

S1 = [[0, 1, 2, 3],
      [2, 0, 1, 3],
      [3, 0, 1, 0],
      [2, 1, 0, 3]]

KEY = ''
msg=''

def permutate(original, fixed_key):
    new = ''
    for i in fixed_key:
        new += original[i - 1]
    return new


def left_half(bits):
    return bits[:int(len(bits)/2)]


def right_half(bits):
    return bits[int(len(bits)/2):]


def shift(bits):
    rotated_left_half = left_half(bits)[1:] + left_half(bits)[0]
    rotated_right_half = right_half(bits)[1:] + right_half(bits)[0]
    return rotated_left_half + rotated_right_half

def key_P10():
    return permutate(KEY, P10)
def key_shift1():
    return shift(key_P10())
def key_shift2():
    return shift(shift(key_shift1()))

def key1():
    return permutate(key_shift1(), P8)

def key2():
    return permutate(key_shift2(), P8)


def xor(bits, key):
    new = ''
    for bit, key_bit in zip(bits, key):
        new += str(((int(bit) + int(key_bit)) % 2))
    return new


def lookup_in_sbox(bits, sbox):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    return '{0:02b}'.format(sbox[row][col])


def f_k(bits, key):
    L = left_half(bits)
    R = right_half(bits)
    bits = permutate(R, EP)
    bits = xor(bits, key)
    bits = lookup_in_sbox(left_half(bits), S0) + lookup_in_sbox(right_half(bits), S1)
    bits = permutate(bits, P4)
    return xor(bits, L)


def encrypt(plain_text):
    bits = permutate(plain_text, IP)
    temp = f_k(bits, key1())
    bits = right_half(bits) + temp
    bits = f_k(bits, key2())
    print('The encryption result is = ' + permutate(bits + temp, IP_INVERSE))
    return permutate(bits + temp, IP_INVERSE)


def decrypt(cipher_text):
    bits = permutate(cipher_text, IP)
    temp = f_k(bits, key2())
    bits = right_half(bits) + temp
    bits = f_k(bits, key1())
    print('The decryption result is = ' + permutate(bits + temp, IP_INVERSE))
    return permutate(bits + temp, IP_INVERSE)


if __name__ == '__main__':
    oper = input('Enter E for encryption and D for decryption：')
    while True:
        flag = 0
        if oper == 'D' or oper == 'd':  #decrypt
            KEY = input('Enter the 10-digit key：')     #get key
            if len(KEY) != 10:  #check key
                print("KEY length error")
                continue
            else:
                for ch in KEY:
                    print(ch)
                    if ch!='1'and ch!='0':
                        flag = 1
                        break
            if flag == 1:
                continue
            msg = input('Enter 8-digit plaintext：')
            if len(msg) != 8:
                print("msg length error")
                continue
            encrypt(msg)
            break
        elif oper == 'E' or oper == 'e':
            KEY = input('Enter the 10-digit key：')
            if len(KEY) != 10:
                print("KEY length error")
                continue
            msg = input('Enter 8-digit ciphertext：')
            if len(msg) != 8:
                print("msg length error")
                continue
            decrypt(msg)
            break
        else: 
            print("illegal input, please try again")
    input('--- Type enter to end the process ---')