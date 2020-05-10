#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2020 Software.Artisan https://github.com/SoftwareArtisan
# For Elijah

import csv
import hashlib
import hmac
import io
import logging
import mimetypes
import os
import sqlite3
import argparse

from dataclasses import dataclass

import sys
from Crypto.Cipher import AES
from Crypto.Util import strxor
from axolotl.kdf.hkdfv3 import HKDFv3

import Backups_pb2

logger = logging.Logger(__name__,level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)
logger.addHandler(handler)

_SIGNAL_DB_NAME = 'signal'

@dataclass
class SignalBackupCrypto(object):
    aes_cipher = None
    backup_key = None
    cipher_key = None
    counter = None
    iv = None
    mac_key = None
    salt = None

    def get_mac(self):
        return hmac.new(self.mac_key, digestmod=hashlib.sha256)

    def bump_counter(self):
        self.counter += 1

    def counter_as_bytes(self):
        return int.to_bytes(self.counter, length=16, byteorder=sys.byteorder)

    def update_iv_from_counter(self):
        val = self.counter_as_bytes()
        self.iv[3] = val[0]
        self.iv[2] = val[1]
        self.iv[1] = val[2]
        self.iv[0] = val[3]


b_crypto = SignalBackupCrypto()
b_proto: Backups_pb2.BackupFrame = Backups_pb2.BackupFrame()


def init_backup(bfile):
    hdr_length = int.from_bytes(bfile.read(4), byteorder='big')
    hdr_frame = bfile.read(hdr_length)
    b_proto.ParseFromString(hdr_frame)

    b_crypto.salt = b_proto.header.salt
    b_crypto.iv = bytearray(b_proto.header.iv)
    b_crypto.counter = int.from_bytes(b_crypto.iv[:4], byteorder='big')
    if len(b_crypto.iv) != 16:
        raise Exception(f'IV wrong size {len(b_crypto.iv)}')


def setup_decrypt(salt, passphrase):
    hash = pp = bytes(passphrase, encoding='ascii')
    digest = hashlib.sha512()
    digest.update(salt)
    for i in range(250000):
        digest.update(hash)
        digest.update(pp)
        hash = digest.digest()
        digest = hashlib.sha512()

    backup_key = hash[:32]
    derivative = HKDFv3().deriveSecrets(backup_key, b'Backup Export', 64)
    cipher_key = derivative[:32]  # 1st 32 bytes
    mac_key = derivative[32:]  # 2nd 32 bytes

    # AES secret key
    aes_cipher = AES.new(cipher_key, AES.MODE_ECB)

    b_crypto.backup_key = backup_key
    b_crypto.cipher_key = cipher_key
    b_crypto.mac_key = mac_key
    b_crypto.aes_cipher = aes_cipher


# app/src/main/java/org/thoughtcrime/securesms/jobs/AttachmentDownloadJob.java
# private static final int    MAX_ATTACHMENT_SIZE = 150 * 1024  * 1024;

def decrypt_frame(bfile, ofile, length, with_iv=False):
    b_crypto.update_iv_from_counter()
    b_crypto.bump_counter()
    mac = b_crypto.get_mac()

    aes_cipher = b_crypto.aes_cipher
    enc_iv = b_crypto.iv
    if with_iv:
        mac.update(b_crypto.iv)

    def get_chunk():
        # Read as many 16 byte chunks as possible
        for i in range(int(length / 16)):
            yield bfile.read(16)
        # Read remainder
        yield bfile.read(length % 16)

    for enc_chunk in get_chunk():
        mac.update(enc_chunk)
        output = strxor.strxor(
            enc_chunk,
            aes_cipher.encrypt(enc_iv)[:len(enc_chunk)]
        )
        ctr = int.from_bytes(enc_iv, byteorder='big') + 1
        enc_iv = int.to_bytes(ctr, length=16, byteorder='big')
        ofile.write(output)

    our_mac = mac.digest()
    our_mac = our_mac[:10]  # trim to 1st 10 bytes
    their_asset_mac = bfile.read(10)

    assert hmac.compare_digest(our_mac, their_asset_mac)


_PARTS_TO_MIME = {}

def process_statement(db,statement):
    if 'CREATE ' in statement.statement and 'sqlite' not in statement.statement:
        db.execute(statement.statement)
        db.commit()
    elif "INSERT INTO " in statement.statement:
        rec = [f'{x}' if isinstance(x, int) and x.bit_length() == 64 else x for x in [p.ListFields()[0][1] for p in statement.parameters]]
        if rec:
            tbl = statement.statement.split(' ')[2]
            if tbl == 'part':
                ext = mimetypes.guess_extension(rec[3])
                if not ext:
                    m1, m2 = rec[3].split('/')
                    ext = mimetypes.guess_extension(f'{m1}/x-{m2}')
                if not ext:
                    ext = 'unk'
                _PARTS_TO_MIME[rec[19]] = rec[3], ext
        db.execute(statement.statement, rec)
        db.commit()
    else:
        if 'sqlite' not in statement.statement:
            db.execute(statement.statement)
            db.commit()


def get_frame(bfile):
    chunk = bfile.read(4)
    frame_length = int.from_bytes(chunk, byteorder='big')

    ofile = io.BytesIO()
    decrypt_frame(bfile, ofile, frame_length - 10)

    # 42, 2, 8, 55
    try:
        b_proto.ParseFromString(ofile.getvalue())
    except Exception as ex:
        print(ex)
        print(bfile.tell())
        print(f'{frame_length}')
        print(f'chunk({chunk})')
        raise


def process_attachment(bfile, length, path):
    try:
        with open(f'{path}', 'wb') as ofile:
            decrypt_frame(bfile, ofile, length, with_iv=True)
    except Exception as ex:
        os.remove(path)
        raise


process_avatar = process_attachment
process_sticker = process_attachment


def to_csv(fn, inp):
    # dt = datetime.datetime.now().strftime("%d-%M-%y-%H:%M:%S")
    # with open(f'{fn}_{dt}.csv', 'w') as outf:
    with open(f'{fn}.csv', 'w') as outf:
        writer = csv.writer(outf)
        writer.writerows(inp)


def process_frame(db,bfile,output_dir):
    get_frame(bfile)

    if b_proto.end:
        logger.info('end of processing')
        return False

    if b_proto.attachment.length:
        logger.debug(f'attach {b_proto.attachment.length}')
        mtypes = _PARTS_TO_MIME.get(b_proto.attachment.attachmentId)
        ext = mtypes[1] if mtypes else '.unk'
        process_attachment(bfile, b_proto.attachment.length, f'{output_dir}/attach_{b_proto.attachment.attachmentId}{ext}')
    if b_proto.statement.statement:
        logger.debug(f'statement {b_proto.statement.statement}')
        process_statement(db,b_proto.statement)
    if b_proto.version.version:
        logger.debug(f'version {b_proto.version.version}')
    if b_proto.avatar.length:
        logger.debug(f'avatar {b_proto.avatar.name}:{b_proto.avatar.length}')
        process_avatar(bfile, b_proto.avatar.length, f'{output_dir}/avatar_{b_proto.avatar.recipientId}')
    if b_proto.preference.file:
        logger.debug(f'preference {b_proto.preference.file} {b_proto.preference.key} {b_proto.preference.value}')
    if b_proto.sticker.length:
        logger.debug(f'sticker {b_proto.sticker.length}')
        process_sticker(bfile, b_proto.sticker.length, f'{output_dir}/sticker_{b_proto.sticker.rowId}.webp')

    return True

def drop_all_tables(db:sqlite3.Connection):
    cur = db.execute('SELECT name, type FROM sqlite_master')
    for row in cur.fetchall():
        logger.debug(row)
        if not row[0].startswith('sqlite_') and 'table' == row[1]:
            db.execute(f'DROP TABLE IF EXISTS {row[0]}')
    db.commit()


def process_backup(backup_fname, passphrase, output_dir):

    try:
        db:sqlite3.Connection = sqlite3.connect(f'{output_dir}/{_SIGNAL_DB_NAME}')
    except:
        logger.exception(f"Can't open or create database {output_dir}/{_SIGNAL_DB_NAME}")
        raise

    drop_all_tables(db)

    with io.open(backup_fname, 'rb', buffering=1024 * 1024) as bfile:
        init_backup(bfile)
        setup_decrypt(b_crypto.salt, passphrase)

        try:
            while process_frame(db,bfile,output_dir):
                pass
        except Exception as ex:
            logger.exception(ex)
        finally:
            logger.info(f'Processing of {backup_fname} ended at byte {bfile.tell()} ')
            db.commit()
            db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Decrypt and export Signal backup file.')
    parser.add_argument('--backup', required=True)
    parser.add_argument('--passphrase', required=True, type=argparse.FileType('r'))
    parser.add_argument('--output', required=True)

    args = parser.parse_args()

    passphrase = args.passphrase.read().replace(' ','').strip()
    if len(passphrase) != 30:
        logger.error(f'Required passphrase is 30 digits not {len(passphrase)}')
        sys.exit(-1)

    if not os.path.exists(args.backup):
        logger.error(f"Backup file {args.backup} doesn't exist.")
        sys.exit(-1)

    if os.path.exists(args.output) and not os.path.isdir(args.output):
        logger.error(f'Output directory is not a directory {args.output}')
        sys.exit(-1)
    else:
        try:
            os.makedirs(args.output, exist_ok=True)
        except:
            logger.exception(f"Can't open or create directory {args.output}")
            sys.exit(-1)

    process_backup(args.backup,passphrase,args.output)
