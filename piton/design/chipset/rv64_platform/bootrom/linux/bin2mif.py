# filepath: /home/aromo/genesys2_riscv/openpiton/piton/design/chipset/rv64_platform/bootrom/linux/bin2mif.py
import sys

def bin_to_mif(bin_file, mif_file, depth, width):
    with open(bin_file, "rb") as f:
        data = f.read()

    with open(mif_file, "w") as f:
        f.write("DEPTH = {};\n".format(depth))
        f.write("WIDTH = {};\n".format(width))
        f.write("ADDRESS_RADIX = HEX;\n")
        f.write("DATA_RADIX = HEX;\n")
        f.write("CONTENT BEGIN\n")

        for i in range(0, len(data), width // 8):
            word = data[i:i + width // 8]
            word_hex = ''.join('{:02X}'.format(b) for b in word)
            f.write("    {:X} : {};\n".format(i // (width // 8), word_hex))

        f.write("END;\n")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: bin2mif.py <bin_file> <mif_file> <depth> <width>")
        sys.exit(1)

    bin_file = sys.argv[1]
    mif_file = sys.argv[2]
    depth = int(sys.argv[3])
    width = int(sys.argv[4])

    bin_to_mif(bin_file, mif_file, depth, width)
