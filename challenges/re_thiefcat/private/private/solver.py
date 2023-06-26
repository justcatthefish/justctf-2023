import socket
import struct

class SpeckCipher(object):
    """Speck Block Cipher Object"""
    __valid_modes = ['ECB', 'CTR', 'CBC', 'PCBC', 'CFB', 'OFB']

    def encrypt_round(self, x, y, k):
        """Complete One Round of Feistel Operation"""
        rs_x = ((x << (self.word_size - self.alpha_shift)) + (x >> self.alpha_shift)) & self.mod_mask

        add_sxy = (rs_x + y) & self.mod_mask

        new_x = k ^ add_sxy

        ls_y = ((y >> (self.word_size - self.beta_shift)) + (y << self.beta_shift)) & self.mod_mask

        new_y = new_x ^ ls_y

        return new_x, new_y

    def __init__(self, key, key_size=128, block_size=128, rounds=32, mode='ECB'):

        # Setup block/word size
        self.block_size = block_size
        self.word_size = self.block_size >> 1

        # Setup Number of Rounds and Key Size
        self.rounds = rounds
        self.key_size = key_size

        # Create Properly Sized bit mask for truncating addition and left shift outputs
        self.mod_mask = (2 ** self.word_size) - 1

        # Mod mask for modular subtraction
        self.mod_mask_sub = (2 ** self.word_size)

        # Setup Circular Shift Parameters
        if self.block_size == 32:
            self.beta_shift = 2
            self.alpha_shift = 7
        else:
            self.beta_shift = 3
            self.alpha_shift = 8

        # Check Cipher Mode
        try:
            position = self.__valid_modes.index(mode)
            self.mode = self.__valid_modes[position]
        except ValueError:
            print('Invalid cipher mode!')
            print('Please use one of the following block cipher modes:', self.__valid_modes)
            raise

        # Parse the given key and truncate it to the key length
        try:
            self.key = key & ((2 ** self.key_size) - 1)
        except (ValueError, TypeError):
            print('Invalid Key Value!')
            print('Please Provide Key as int')
            raise

        # Pre-compile key schedule
        self.key_schedule = [self.key & self.mod_mask]
        l_schedule = [(self.key >> (x * self.word_size)) & self.mod_mask for x in
                      range(1, self.key_size // self.word_size)]

        for x in range(self.rounds):
            new_l_k = self.encrypt_round(l_schedule[x], self.key_schedule[x], x)
            l_schedule.append(new_l_k[0])
            self.key_schedule.append(new_l_k[1])

        self.key_schedule = self.key_schedule[1:]

        self.key_schedule = [self.key_schedule[4 ^ i] for i in range(len(self.key_schedule))]

    def encrypt(self, plaintext):
        try:
            b = (plaintext >> self.word_size) & self.mod_mask
            a = plaintext & self.mod_mask
        except TypeError:
            print('Invalid plaintext!')
            print('Please provide plaintext as int')
            raise

        if self.mode == 'ECB':
            b, a = self.encrypt_function(b, a)

        ciphertext = (b << self.word_size) + a

        return ciphertext

    def decrypt(self, ciphertext):
        try:
            b = (ciphertext >> self.word_size) & self.mod_mask
            a = ciphertext & self.mod_mask
        except TypeError:
            print('Invalid ciphertext!')
            print('Please provide plaintext as int')
            raise

        if self.mode == 'ECB':
            b, a = self.decrypt_function(b, a)

        plaintext = (b << self.word_size) + a

        return plaintext

    def encrypt_function(self, upper_word, lower_word):
        x = upper_word
        y = lower_word

        # Run Encryption Steps For Appropriate Number of Rounds
        for k in self.key_schedule:
            rs_x = ((x << (self.word_size - self.alpha_shift)) + (x >> self.alpha_shift)) & self.mod_mask
            add_sxy = (rs_x + y) & self.mod_mask
            x = k ^ add_sxy
            ls_y = ((y >> (self.word_size - self.beta_shift)) + (y << self.beta_shift)) & self.mod_mask
            y = x ^ ls_y
        return x,y


    def decrypt_function(self, upper_word, lower_word):
        x = upper_word
        y = lower_word

        # Run Encryption Steps For Appropriate Number of Rounds
        for k in reversed(self.key_schedule):
            xor_xy = x ^ y
            y = ((xor_xy << (self.word_size - self.beta_shift)) + (xor_xy >> self.beta_shift)) & self.mod_mask
            xor_xk = x ^ k
            msub = ((xor_xk - y) + self.mod_mask_sub) % self.mod_mask_sub
            x = ((msub >> (self.word_size - self.alpha_shift)) + (msub << self.alpha_shift)) & self.mod_mask
        return x,y




a = 0xc7b883235162dde5
b = 0x8d4bd7bd1949d184

a = (((a << 2) | (a >> 62)) & 0xffffffffffffffff) ^ (0x5d65fa8fe0597fba + 0xe57be1f87805f69e)
b = ((((b >> 3) | (b << 61)) & 0xffffffffffffffff) - (0x1c917d1ac9ac64a9 ^ 0xe57be1f87805f69e) + 0xffffffffffffffff + 1) & 0xffffffffffffffff

reply = b'K\xb9\xa5\x19\x9b\x18y\xdc\xad\xb0\x112I\x01\tJ\xed\xa7N\x0c\x95{\x0b$\x97J\xb0\\p\n\xf5\xaf'

pr1, pr2 = 0, 0
result = b''
for i in range(2):
    cdata = reply[16*i:16*i+16]

    x, y = struct.unpack('<QQ', cdata)

    r1, r2 = SpeckCipher((a << 64) | b, rounds=40).decrypt_function(x, y)
    result += struct.pack('<QQ', r1^pr1, r2^pr2)
    pr1, pr2 = x, y

print(result)