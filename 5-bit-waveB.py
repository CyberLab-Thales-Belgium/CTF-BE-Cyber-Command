import wave

with wave.open("5-waveB.wav", "r") as fwave:
    n_channels = fwave.getnchannels()
    sample_width = fwave.getsampwidth()
    n_samples_per_packet = 4
    samplesList = []
    samples = fwave.readframes(n_samples_per_packet)
    while samples:
        for i in range(0, len(samples), sample_width * n_channels):
            sample = int.from_bytes(samples[i:i+sample_width], byteorder="little", signed=True)
        samples = fwave.readframes(n_samples_per_packet)
        samplesList.append(sample)
#Extract the flag
byteCode = ''.join('0' if byte == 0 else '1' for byte in samplesList)
print("ByteCode:", byteCode)
part1 = byteCode[::2]
part2 = byteCode[1::2]
xored = ''.join(str(int(part1[i]) ^ int(part2[i])) for i in range(len(part1)))
byte_array = [int(xored[i:i+8], 2) for i in range(0, len(xored), 8)]
flag = ''.join(map(chr, byte_array))
print('Fl4g:', flag)
