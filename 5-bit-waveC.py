import wave

with wave.open("5-waveC.wav", "r") as fwave:
    n_channels = fwave.getnchannels()
    sample_width = fwave.getsampwidth()
    n_samples_per_packet = 8
    samplesList = []
    samples = fwave.readframes(n_samples_per_packet)
    while samples:
        for i in range(0, len(samples), sample_width * n_channels):
            sample = int.from_bytes(samples[i:i+sample_width], byteorder="little", signed=True)
        samples = fwave.readframes(n_samples_per_packet)
        samplesList.append(sample)
#Extract the flag
byteCode = ""
for byte in samplesList:
    byteCode += "1" if byte in [8000, 16000] else "0"
print("ByteCode:", byteCode)
byte_array = [int(byteCode[i:i+8], 2) for i in range(0, len(byteCode), 8)]
flag = ''.join(map(chr, byte_array))
print('Fl4g:', flag)
