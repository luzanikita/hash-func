import argparse
import base64


class MD2:
    S = [
        41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
        76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
        245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
        39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
        150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
        96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
        234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
        8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
        166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20
    ]

    def padding(self, message: list) -> list:
        messageLenght = len(message)
        bytesToAdd = 16 - (messageLenght % 16)
        message.extend([bytesToAdd for i in range(bytesToAdd)])

        return message

    def checksum(self, message: list) -> list:
        l = len(message)
        L = 0
        checkSum = [0 for i in range(16)]

        for i in range (l//16):
            for j in range(16):
                c = message[16*i + j]
                checkSum[j] = checkSum[j] ^ self.S[ c ^ L ]
                L = checkSum[j]

        return message + checkSum

    def hash(self, message: list) -> list:
        l = len(message)
        X = [0 for i in range(48)]

        for i in range (l//16):
            for j in range(16):
                X[j + 16] = message[ 16*i + j]
                X[j + 32] = X[j + 16] ^ X[j]

        t = 0
        for j in range(18):
            for k in range(48):
                t = X[k] ^ self.S[t]
                X[k] = t
                t = (t + j) % 256

        return ''.join([format(X[i], 'x').zfill(2) for i in range(16)])

    def sign(self, message: str) -> str:
        message = message.strip('\"')
        hexMessage = [ord(char) for char in message]
        paddedMessage = self.padding(hexMessage)
        messageWithcheckSumhecksum = self.checksum(paddedMessage)
        signature = self.hash(messageWithcheckSumhecksum)

        return signature


def main(length, input_file, output_file):
    with open(input_file, 'r') as f:
        data = f.read()
        input_bytes = base64.b64encode(data.encode('utf-8'))
        input_str = str(input_bytes, 'utf-8')
    
    md2 = MD2()
    digest = md2.sign(input_str)

    cropped_digest = digest[-length:]

    with open(output_file, 'w') as f:
        f.write(cropped_digest)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run encryption.')
    parser.add_argument(
        '-l', '--length', default=1, dest='length', help='Hash length in bytes.'
    )
    parser.add_argument(
        '-i', '--input', required=True, dest='input_file', help='Input file.'
    )
    parser.add_argument(
        '-o', '--output', required=True, dest='output_file', help='Output file.'
    )

    args = parser.parse_args()
    main(int(args.length), args.input_file, args.output_file)
