import argparse
import base64

from hash_func import MD2


def calc_digest(length, data):
    input_bytes = base64.b64encode(data.encode('utf-8'))
    input_str = str(input_bytes, 'utf-8')
    md2 = MD2()
    digest = md2.sign(input_str)
    cropped_digest = digest[-length:]

    return cropped_digest


def main(length, original_file, fake_file):
    with open(original_file, 'r') as f:
        original_data = f.read()
    original_digest = calc_digest(length, original_data)

    with open(fake_file, 'r') as f:
        fake_data = f.read()
    fake_digest = calc_digest(length, fake_data)

    attempts = 1
    while fake_digest != original_digest:
        attempts += 1
        fake_data += ' '
        fake_digest = calc_digest(length, fake_data)
    
    print('attempts:', attempts)
    with open(fake_file, 'w') as f:
        f.write(fake_data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run encryption.')
    parser.add_argument(
        '-l', '--length', default=1, dest='length', help='Hash length in bytes.'
    )
    parser.add_argument(
        '-o', '--original_file', required=True, dest='original_file'
    )
    parser.add_argument(
        '-f', '--fake_file', required=True, dest='fake_file'
    )

    args = parser.parse_args()
    main(int(args.length), args.original_file, args.fake_file)