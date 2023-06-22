# Mifare DESFire EV1/2/3 Examples (DES keys) using NFCjLib

This app is using the NFCjLib library from **Desfire Tools for Android** available on GitHub here:
https://github.com/skjolber/desfire-tools-for-android.

It was written by Thomas Skjølberg ("skjolber") and this one is the best available source for accessing 
NXP's Mifare DESFire tags. 

If you are trying to get basic information's about the DESFire tag the first contact point is the  manufacturer's datasheet, available here:
- DESFire EV1 MF3ICDX21_41_81_SDS: https://www.nxp.com/docs/en/data-sheet/MF3ICDX21_41_81_SDS.pdf
- DESFire EV2 MF3DX2_MF3DHX2_SDS: https://www.nxp.com/docs/en/data-sheet/MF3DX2_MF3DHX2_SDS.pdf
- DESFire EV3 MF3D(H)x3: https://www.nxp.com/docs/en/data-sheet/MF3DHx3_SDS.pdf
- DESFire EV3 Quick start guide: https://www.nxp.com/docs/en/application-note/AN12753.pdf
- DESFire EV3 feature and functionality comparison to other MIFARE DESFire products: https://www.nxp.com/docs/en/application-note/AN12752.pdf

Unfortunately the 3 main datasheets are shortened by the manufacturer and the full datasheets are available under **Non disclosure agreements (NDA)** only - 
the agreement is not available for private persons.

So the only chance is to use the **datasheet for the first version of DESFire tags ("D40")** using this link:
https://neteril.org/files/M075031_desfire.pdf

Another fine piece of information is the **NXP MIFARE DESFire EV1 Protocol** available here: https://github.com/revk/DESFireAES/blob/master/DESFire.pdf. 
This is a short overview about most of the DESFire EV1 commands and error codes.

## About this app: 
It is developed using Android Studio version Flamingo | 2022.2.1 Patch 2n and is running on SDK 21 to 33 (Android 13) (tested on 
Android 8 and 13 with real devices).  

The main purpose of the app is to run all major functions of a DESFire tag in one application using **DES keys** and **plain  / open communication**.

This should be the perfect beginner app as it uses a brand new DESFire tag with it's factory settings.

Some notes on typical sessions with the card 

### 01 tap the DESFire tag to the NFC reader of an Android phone 
The app connects to the tag and read the **tag id** (7 bytes long)

### 02 select an application on the card
A brand new tag ships with one application on the card called the **Master Application** that has the **application id** '000000'. This application has one 
purpose: it hold the **Master Application Key** (meaning the main key of the tag) and some general application settings that are valid for all applications   
on the tag.

Note: see position xx (key settings) for a more detailed explanation on this.

If there is additional applications they are shown in an Alert Dialog and by clicking on the entry this application is selected for further work with.

### 03 create an application
There are two edit fields above the button:
- application id: an application has a 3 byte long application id ("AID") that is defined here using 6 6 characters long hex encoded string. As default 
the AID 'A1A2A3' is preset in the field but you can edit this field to your purposes
- number of keys: each application can hold 14 individual keys, this app uses 5 key numbers as default. Please do not use a smaller number because this 
method is using the 5 keys for these different rights (hardcoded in the source code):

**Key 0: is the application master key** (don't mix it with the Master Application Key that is available only in the  Master Application). The main purpose 
of this key is to authorize any key related authentications.

**Key 1: is the read & write access key**. When the application is authenticated with this key every read AND write operation is authenticated for every **file** 
within this application.

**Key 2: is the change access key**. During application creation the total number of keys are setup and this is not changeable but we can change the key number 
for the specific right (e.g. we can change the read & write key from key 1 to key number 7 IF we setup 8 keys for this application [the counting starts on 0...]).

**Key 3: is the read access key** - if we want to read from a file this right has to authenticated in advance.

**Key 4: is the write access key** - if we want to write to a file this right has to authenticated in advance.

Note: see position xx (authentication) for a more detailed explanation on this.



