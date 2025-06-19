## Disclaimer

This is all the result of reverse engineering or finding information on the internet.
If you find mistakes or want to add information, a PR would be appreciated.

## What it does

Parses the [Aztec](https://en.wikipedia.org/wiki/Aztec_Code) code data of a Deutschlandticket.
It is only a dumb parser so far.
It doesn't do any signature verification or further processing.
Feel free to add this functionality with a pull request.

## How to use

> I recommend [Binary Eye](https://play.google.com/store/apps/details?id=de.markusfisch.android.binaryeye) for the first two steps.

1. Scan your Deutschlandticket Aztec code, e.g., by making a screenshot and scanning it with a Aztec code scanner capable of doing so from an image file.
2. Store the data in a file called 'aztec.bin'
3. Copy this file into the main directory of this repository
4. Execute `python3 main.py`

## Technical details

The Deutschlandticket Aztec code is distributed as a VDV-barcode
defined in the VDV-Kernapplikation (VDV-KA).
See: https://docplayer.org/61642532-Spezifikation-statischer-berechtigungen-fuer-2d-barcode-tickets.html
Section 4.3

The Deutsche Bahn (DB) usually uses the UIC standard
for their distribution of tickets. However, they start to integrate
the VDV-KA standard as well, e.g., for Schönes-Wochenende-Ticket, Quer-Durchs-Land-Ticket, Länder-Tickets, City-Ticket,
and City-mobil. And apparently now for the Deutschlandticket as well.
See [Interoperabilität Barcode DB Online-Ticket VDV-KA](https://www.eticket-deutschland.de/media/vdv-ets_whitepaper-barcode_oepnv.pdf)
for more information about the compatibility between the UIC and the VDV-KA standard.
In a nutshell, they use the same Aztec 2D-barcode representation,
but after scanning the ticket it needs to be processed differently.
