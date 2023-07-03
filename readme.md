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
https://neteril.org/files/M075031_desfire.pdf.

Another fine piece of information is the **NXP MIFARE DESFire EV1 Protocol** available here: https://github.com/revk/DESFireAES/blob/master/DESFire.pdf. 
This is a short overview about most of the DESFire EV1 commands and error codes.

## About this app: 
It is developed using Android Studio version Flamingo | 2022.2.1 Patch 2n and is running on SDK 21 to 33 (Android 13) (tested on 
Android 8 and 13 with real devices).  

The main purpose of the app is to run all major functions on a DESFire tag in one application using **DES keys** and **plain / open communication**.

This should be the perfect beginner app as it uses a brand new DESFire tag with it's factory settings.

Some notes on typical sessions with the card: I recommend that you lay your phone on the tag and after the connection don't move the phone to hold the 
connection.

### 01 tap the DESFire tag to the NFC reader of an Android phone 
The app connects to the tag and read the **tag id** (7 bytes long)

### 02 select an application on the card
A brand new tag ships with one application on the card called the **Master Application** that has the **application id** '000000'. This application has one 
purpose: it holds the **Master Application Key** (meaning the main key of the tag) and some general application settings that are valid for all applications   
on the tag.

Note: see position xx (key settings) for a more detailed explanation on this.

If there are additional applications they are shown in an Alert Dialog and by clicking on the entry this application is selected for further work with. 
The 'Master Application' is not shown in the Alert Dialog. If no application is shown we need to create an application (see step 03).

### 03 create an application
There are two edit fields above the button:
- application id: an application has a 3 byte long application id ("AID") that is defined here using a 6 characters long hex encoded string. As default 
the AID 'A1A2A3' is preset in the field but you can edit this field to your purposes
- number of keys: each application can hold up to 14 individual keys, this app uses 5 key numbers as default. Please do not use a smaller number because this 
method is using the 5 keys for these different rights (hardcoded in the source code):

**Key 0: is the application master key** (don't mix it with the Master Application Key that is available only in the  Master Application). The main purpose 
of this key is to authorize change key authentications.

**Key 1: is the read & write access key**. When the application is authenticated with this key every read AND write operation is authenticated for every **file** 
within this application.

**Key 2: is the change access key**. During application creation the total number of keys are setup and this is not changeable but we can change the key number 
for the specific right (e.g. we can change the read & write key from key 1 to key number 7 IF our setup was 8 keys for this application [the counting starts on 0...]).

**Key 3: is the read access key** - if we want to read from a file this right has to get authenticated in advance.

**Key 4: is the write access key** - if we want to write to a file this right has to get authenticated in advance.

Note: see position xx (authentication) for a more detailed explanation on this.

The new application is created immediately after pressing the 'create' button. There are 2 important information fields on the top:
- **operation output**: a short summary of the commands and outputs is given
- **error code**: if the border is 'green' the operation was successful and if the border is 'red' the operation failed. The reason for the failure 
is given (e.g. when creating the same application id 2 times the second creation fails with a 'Duplicate Error').

The new application is NOT selected so if you want to (e.g.) create a file you need to select the application (see step 02).

### 04 select a file
All data operations are done with **files** in an application, so to read from or write to a file we need to select the file in the preselected 
application.

If there are any files in this applications the **file id's** are shown with the file type in the Alert Dialog and we select the file by clicking on it.
If no file is shown we need to create a file (see steps 05 ff).

### 05 create a file
The main parameter for a file is it's **file id** that has to be in the range of 00 to 14 so in total 15 files are available for each application. 
This limit is larger in EV2 and EV3 cards but to hold compatibility to even the oldest tag types I'm using this limit. Select the file id with 
the number picker.

There is NO method available to 'create a file' because a DESFire tag supports 5 different types of files that have their own parameter sets and 
this app has different buttons to create a file for the specific file type:
- **A standard file**: this file type should be used for 'read only' operations, meaning that the data in this field is written on the tag during personalization 
but is later no longer changed. Each standard file has a file size that is setup on creation that is not changeable later. As a default I'm setting the 
file size to 32 in the next edit text field. Please keep in mind that internally a file is setup in multiples of 32 bytes, so a 1 byte long standard file 
consumes 32 bytes on the tag.
- **B backup file**: not implemented so far. A backup file is written like a standard file but only after a successful 'commit' command the new content 
is set and visible for later readings. Use these kind of files if you want to write data to the tag in daily use.
- **C value file**: think of a prepaid application like a cafeteria card: you buy the card with a credit value, when later buying a coffee the amount 
is debited from the card and if you want to recharge your card the card is credited by the cashier. A value file is created by 4 additional parameters:
- **lower limit of the value**: usually the lower limit is set to 0 because otherwise the tag would be a "credit card". If you want to debit an amount that 
the balance would be lower than the lower limit the operation is declined by the card. The default value is 0.
- **upper limit of the value**: this is the maximum value the card card can get credited (or "recharged"). If you want to credit an amount that increases 
the upper limit the transaction is declined. The default upper limit is set to 500. 
- **initial value**: during creation this value is setup as value on the card. The default value is 100.
- **limited credit available**: this feature is hardcoded set to "disabled". If enabled the card supports one crediting after a successful authentication on 
a previous credit action.
- **D Linear Record file**: The records have a record size that is setup during creation of the file and the size is not changeable later. The second parameter 
is the total number of entries (records) in this files (default setting: 5 records). If you are writing to the file a new record is stored up the maximum of 
records; trying to save more records will fail. See xx (delete file) for more information on file handling. 
- **E Cyclic Record file**: A Cyclic record file uses the same parameters as the Linear Record file (record size and maximum number of records). The different 
is the behavior when writing additional records than the tag: the card will overwrite the oldest record so there is "space" for the new record. For this cycling 
operation a 'spare record' is needed so in practise you can write 'total number of entries - 1' only to the Cyclic Record file. This file type is perfect 
to log data on the tag. 

After a file creation this file is not preselected but need to get selected (see step 04) if you want to work with. 

### 06 read from a file
After file selection the selected file is read after a successful authentication with the **read & write access key** or **read access key** is done. As each 
file type has its own specifications you need to read from the file in the correct section. The methods reads out the file type from the card and print out 
these data:
- standard file: the complete data in the file is shown in a hex encoded string and additionally the (UTF-8) string data is given  
- backup file: same to standard file
- value file: the value = 'balance' is printed out
- Linear Record file: the complete data in the file **and all records** is printed out in hex string encoded data and as (UTF-8) string.
- Cyclic Record file: same to Linear Record file 

As a record file can consist of 100 or more records (depending on the tags memory) a lot of data is printed out. If you already know about this situation 
consider about using offsets for reading (not implemented in the app).

### 07 write to a file
Same to file creation there is no single method but 3 methods to write to a file of different file types (see step 03, create a file):
- standard file: the complete data in the file is overwritten by the new data (if the file size is larger than the data the data is filled up with 0x00 bytes.
- backup file: same to standard file
- value file: you cannot write a new value directly. Instead there are two methods to change the value ('balance'): you can either **credit a value** or 
**debit a value**. On file creation we defined the lower and upper limits and when crediting an amount and the new value ('balance') would be greater 
than the upper limit the transaction is canceled. The same behaviour is with debiting - trying to get a lower value than the  lower limit will cause a failure. 
- Linear Record file: A new record is written to the tag up to the maximum number of records. Any further writing will be declined.
- Cyclic Record file: A new record is written to the tag up to the maximum number of records. Any further writing will overwrite the oldest record in the file. 
Remember that the maximum number of records include a 'spare record' for the cycling behavior - there are (maximum number of records - 1) only available for 
writing and (later) reading.

**Important note:** while writing to a standard file is done immediately **the writing to the other files type does need an additional step** 
that is called **commit** (see step 08 commit).

### 08 commit a write command

For (data) security and integrity reasons the writing of data to the tag isn't done in one step (like writing to a standard file) 
but in 2 steps - the writing of data and followed by a 'commit' command. Think about writing of some hundreds of bytes to the card and during the process of writing 
the tag is moved out of the reader ('terminal') device. This would cause that some data may be written but some could not get written - that is a bad situation. 
The two step writing takes care of that situation. When somethings happens during the first phase all written data get invalidated.  

The commit command is necessary using these commands: write to a Backup file, credit a Value file, debit a Value file, write to a Linear Record File and write to a 
Cyclic Record file.

Only when the write process was successful the data is really confirmed with the commit command. In my app all dedicated write commands are followed by the commit 
command.

### 09 authentication

Note: for the purpose of an easy access the user interface has a lot of buttons to run the desired action. 

As mentioned in step 03 (create an application) there are different keys available within a tag). Each key has its own purpose:



```plaintext
Example DES session key (16 bytes)
The random A is a6 01 73 75 8e 1d 29 8f
The random B is 6a 3e 01 a8 53 06 37 5d
The skey     is a6 01 73 75 6a 3e 01 a8
                A0 A1 A2 A3 B0 B1 B2 B3 

rndA length: 8  b8 75 bc 4d e2 0f 45 07
rndB length: 8  f6 3a 13 02 a7 d8 89 9b


Example AES session key (16 bytes)
The random A is dd 62 af 26 90 75 27 99 07 99 78 31 f2 c7 37 40
The random B is b7 05 8d 1e 27 ce 03 db 07 cb d0 13 3b bd 42 55
The skey     is dd 62 af 26 b7 05 8d 1e f2 c7 37 40 3b bd 42 55
                A0 A1 A2 A3 B0 B1 B2 B3 A12A13A14A15B12B13B14B15
The skey     is dd 62 af 26 b7 05 8d 1e f2  c7  37  40  3b  bd  42  55
                A0 A1 A2 A3 B0 B1 B2 B3 A12 A13 A14 A15 B12 B13 B14 B15                
                
```
