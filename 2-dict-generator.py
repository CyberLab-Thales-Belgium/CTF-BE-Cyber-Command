dictCTF = []
special = [" ","!","\"","#","$","%","&", "\'","(",")","*","+",",","-",".","/",":",";","<","=",">","?","@","[","\\","]","^","_","`","{","|","}","~","]"]
with open("2-wordlist.txt", "r", encoding="utf-8") as f:
    for line in f:
        for i in range(1950, 2023):
            for s in special:
                dictCTF.append(line.capitalize().replace(" ","").replace("\n", "") + str(i) + s)

with open("dictCTF.txt", "w", encoding="utf-8") as output:
    output.write('\n'.join(str(i) for i in dictCTF))
