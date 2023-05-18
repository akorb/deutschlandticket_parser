## What it does

Parses the QR code data of a Deutschlandticket.
It is only a dumb parser so far.
It doesn't do any signature verification or further processing.
Feel free to add this functionality with a pull request.

## How to use

> I recommend [Binary Eye](https://play.google.com/store/apps/details?id=de.markusfisch.android.binaryeye) for the first two steps.

1. Scan your Deutschlandticket QR code, e.g., by making a screenshot and scanning it with a QR code scanner capable of doing so from an image file.
2. Store the data in a file called 'qr.bin'
3. Copy this file into the main directory of this repository
4. Execute `python3 main.py`
