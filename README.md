# signal-backup-exporter

`signal-backup-exporter` is a [Python3](https://www.python.org/) script that takes
a version 55 or prior [Signal](https://github.com/signalapp) backup file and exports 
the contents to a [SQLite](https://sqlite.org/index.html) DB file as well as all the
image, document and attachments.

The script serves as the basis for saving the contents of the backup more accessible to the casual programming community.

As of May 10th, 2020, the script is _**RAW**_, somewhat slow for large backups and more of a POC than a product.
I am putting it out into the world in-case anyone else is looking to unlock their Signal messages.

Moxie and company put a lot of effort into securing your private information, so, in case this isn't obvious:

__WARNING__ unencrypt the contents of your Signal backup and save on a secure platform.

The script is similar in nature to [Alex Smith's (Xeals) Signal-Back](https://github.com/xeals/signal-back) Go program
but with, hopefully, a easier threshold for folks who want to extract and post-process the backup data.

The script was significantly easier to write due to the efforts of:

  * [Helder Eijs (Legrandin)](https://github.com/Legrandin/pycryptodome) PyCryptodome
  * [Tarak (tgalal)](https://github.com/tgalal/python-axolotl) Python-Axolotl (Python port of [libsignal](https://github.com/WhisperSystems/libaxolotl-android))

# Required Components

Python 3.7+  
[pycryptodome](https://github.com/Legrandin/pycryptodome)  
[python-axoltl](https://github.com/tgalal/python-axolotl)  
[protobuf](https://github.com/protocolbuffers/protobuf/tree/master/python) - [Installing Python binding](https://github.com/protocolbuffers/protobuf/tree/master/python)

## For development

Google's protobuf compiler:  
  * brew install protobuf (MacOS)
  * compile: protoc -I=... --python_out=... Backups.proto

# Installation

pip install -r requirements.txt

# Usage

signal_backup_exporter.py  
--backup < Signal backup file >  
--passphrase < file with 30 character backup passphrase >  
--output < directory where contents are dumped >  

Attachments and the SQLite DB **signal.db** are saved in the output directory.

# Future/On-going Improvements

* Export to XML in a format consumable by Android SMS/MMS backup/restore programs.
* Generate local web site of message contents/attachments.

# License

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html

__For Elijah__

Copyright (C) 2020 Software.Artisan 