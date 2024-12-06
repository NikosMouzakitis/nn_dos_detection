# Open the file NORMAL_IDS.txt to read and dos_idx.txt to write
with open('NORMAL_IDS.txt', 'r') as infile, open('dos_idx.txt', 'w') as outfile:
    # Read each line in NORMAL_IDS.txt
    for line in infile:
        # Write the current line to dos_idx.txt
        outfile.write(line)
        outfile.write(" 0000\n")
        outfile.write(" 0000\n")
        outfile.write(" 0000\n")
