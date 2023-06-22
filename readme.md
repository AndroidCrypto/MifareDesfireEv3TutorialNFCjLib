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

Some notes on typical sessions with the card. I recommend that you lay your phone on the tag and after the connection don't move the phone to hold the 
connection:

### 01 tap the DESFire tag to the NFC reader of an Android phone 
The app connects to the tag and read the **tag id** (7 bytes long)

### 02 select an application on the card
A brand new tag ships with one application on the card called the **Master Application** that has the **application id** '000000'. This application has one 
purpose: it hold the **Master Application Key** (meaning the main key of the tag) and some general application settings that are valid for all applications   
on the tag.

Note: see position xx (key settings) for a more detailed explanation on this.

If there are additional applications they are shown in an Alert Dialog and by clicking on the entry this application is selected for further work with. 
The 'Master Application' is not shown in the Alert Dialog. If no application is shown we need to create an application (see step 03).

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

The new application is created immediately after pressing the 'create' button. There are 2 important information fields on the top:
- **operation output**: a short summary of the commands and outputs is given
- **error code**: if the border is 'green' the operation was successful and if the border is 'red' the operation failed. The reason for the failure 
is given (e.g. when creating the same application id 2 times the second creation fails with a 'Duplicate Error').

The new application is NOT selected so if you want to (e.g.) create a file you need to select the application (see step 02).

### 04 select a file
All data operations are done with **files** in an application, so to read from or write to a file we need to select this file in the preselected 
application.

If there are any files in this applications the **file id's** are shown in the Alert Dialog and we select the file by clicking on it.
If no file is shown we need to create a file (see steps 05 ff).

### 05 create a file
The main parameter for a file is it's **file id** that has to be in the range of 00 to 14 so in total 15 files are available for each application. 
This limit is longer given in EV2 and EV3 but to hold compatibility to even the oldest tag types I'm using this limit. Select the file id with 
the number picker.

There is NO method available to 'create a file' because the DESFire tag supports 5 different types of files that have their own parameter sets and 
this app has different buttons to create a file for the specific file type:
- **A standard file**: this file type should be used for 'read only' operations, meaning that the data in this field is set on tag personalization 
but is later no longer changed. Each standard file has a file size that is setup on creation that is not changeable later. As a default I'm setting the 
file size to 32 in the next edit text field. Please keep in mind that internally a file is setup in multiples of 32 bytes, so a 1 byte long standard file 
consumes 32 bytes on the tag.
- **B backup file**: not implemented so far
- **C value file**: think of a prepaid application like a cafeteria card: you buy the card with a credit value, when later buying a coffee the amout 
is debited from the card and if you want to recharge your card the card is credit by the cashier. A value file is created by 4 additional parameters:
- **lower limit of the value**: usually the lower limit is set to 0 because otherwise the tag would be a "credit card". If you want to debit an amount that 
the balance would be lower than the lower limit the operation is declined by the card.
- **upper limit of the value**: this is the maximum value the card card can get credited (or "recharged"). If you want to credit an amount that increases 
the upper limit the transaction is declined. The default upper limit is set to 500. 
- **initial value**: during creation this value is setup as value on the card. The default value is 100.
- **limited credit available**: this feature is hardcoded set to "disabled". If enabled the card supports one crediting after a successful authentication on 
a previous credit action.  


