#!/usr/bin/python

import urllib
import zipfile
import os

urllib.urlretrieve (r"http://s3.amazonaws.com/alexa-static/top-1m.csv.zip", r"top-1m.csv.zip")
with zipfile.ZipFile(r"top-1m.csv.zip", "r") as z:
	z.extractall()

alexa_csv = open("top-1m.csv").readlines()
alexa = open("top-1m.txt", 'w')

alexa.write('#fields\tdomain\n')
for line in alexa_csv:
	domain = line.split(",")[1]
	alexa.write(domain)

alexa.close()
os.remove("top-1m.csv")
os.remove("top-1m.csv.zip")
