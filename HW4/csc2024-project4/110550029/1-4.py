#!/usr/bin/env python3
'''
ffd8 and ffd9 are the magic numbers for jpeg files, which represent the start and end of the file respectively
The data after ffd9 is another PNG file showing the flag
'''
# Run on MacOS
from PIL import Image
import pytesseract
import sys
import os

name = 'output.png'
input = open(sys.argv[1], 'rb')
output = open(name, 'wb')
input.read(0x6b20)
output.write(input.read())

image = Image.open(name)
text = pytesseract.image_to_string(image, lang='eng')
print(text, end='')
#os.remove(name)