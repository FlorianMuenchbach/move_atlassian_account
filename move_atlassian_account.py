#!/usr/bin/python3

import csv
import logging
import shutil
import sys
import os
from getpass import getpass

from movers.bitbucket import BitbucketMover

FORMAT = '%(levelname)-10s %(message)s'
logging.basicConfig(format=FORMAT)

logger = logging.getLogger('User move')
logger.setLevel(logging.DEBUG)


class CredentialCache:
    class Account:
        user = None
        password = None
        def valid(self):
            return self.user is not None and self.password is not None
        def reset(self):
            self.user = CredentialCache.Account.user
            self.password = CredentialCache.Account.password

    old = Account()
    new = Account()

    def valid(self):
        return self.old.valid() and self.new.valid()

    def reset(self):
        self.old.reset()
        self.new.reset()


def get_interactive_yes_no(message, default_yes=False):
    answer=None
    while True:
        answer = input(f'{message} [{"Y|n" if default_yes else "y|N"}] ')
        if (answer == "" and default_yes) or answer.lower() == "y":
            return True
        elif (answer == "" and not default_yes) or answer.lower() == "n":
            return False
        else:
            continue


def print_separator():
    term_width = shutil.get_terminal_size((50, 1)).columns
    print(f'{"".join(["-"] * term_width)}')

def get_account(account, url, prefix=""):
    while not account.valid():
        print_separator()
        print(f'{prefix} credentials')
        try:
            account.user = input('\tuser name: ')
            account.password = getpass('\tpassword: ')
        except KeyboardInterrupt:
            print("\nInterrupted.")
            sys.exit(0)


        if account.valid() and BitbucketMover.test_login(url, account):
            logger.info(f'Got working credentials for %s', prefix)
        elif get_interactive_yes_no('Failed! Try again?', default_yes=True):
            logger.error('Did not get working credetials for %s.', prefix)
            account.reset()
        else:
            account.reset()
            break
    logger.info('Account %s configured.', account.user)




def get_credetials(url):
    creds = CredentialCache()
    get_account(creds.old, url, "Old Account")
    get_account(creds.new, url, "New Account")

    return creds if creds.valid() else None

def read_mappings(mapping_file):
    mapping={}
    try:
        with open(mapping_file, 'r') as f:
            for row in csv.reader(f, delimiter=','):
                mapping[row[0]] = row[1]
    except:
        logger.error('Failed to open %s', mapping_file)
        return None
    return mapping

def get_mapping():
    mapping_file = None
    mapping = None
    if get_interactive_yes_no(
            'Use mapping file (csv, first column: old ID, second: new ID)?',
            default_yes=True):
        while not mapping_file or os.path.isfile(mapping_file) or not mapping:
            mapping_file = input('Mapping path: ')
            mapping = read_mappings(mapping_file)
            if mapping:
                logger.info('Using mapping from %s', mapping_file)
                break
            elif get_interactive_yes_no('Mapping file empty (or error...), continue without?'):
                mapping = None
                break
            else:
                continue
    return mapping

def get_avatars():
    avatar_file = None
    avatar = bytes()
    set_avatar = get_interactive_yes_no(
            'Use "deprecated account" avatar file (png only!)?',
            default_yes=True)

    if set_avatar:
        while not avatar_file or os.path.isfile(avatar_file) or not avatar:
            avatar_file = input('Avatar path: ')
            try:
                with open(avatar_file, 'rb') as f:
                    avatar = f.read()
            except:
                logger.error('Failed to open %s', avatar_file)

            if avatar:
                logger.info('Using Avatar from %s', avatar_file)
                break
            elif get_interactive_yes_no(
                    'Avatar file empty (or error...), continue without? [Y|n] '):
                avatar = bytes()
                break
            else:
                continue
    return set_avatar, avatar




def main():
    BITBUCKET_URL = None
    while not BITBUCKET_URL or not BitbucketMover.test_connection(BITBUCKET_URL):
        print_separator()
        BITBUCKET_URL = input('Specify Bitbucket URL: ')
        BITBUCKET_URL = BITBUCKET_URL[:-1] if BITBUCKET_URL.endswith('/') else BITBUCKET_URL


    credentials = get_credetials(BITBUCKET_URL)
    mapping = get_mapping()
    set_avatar, avatar = get_avatars()

    bmover = BitbucketMover(credentials, BITBUCKET_URL)

    print_separator()
    _unused = input('End of interactive part. Hit return to continue (CTRL+C to cancel): ')
    print_separator()

    return
    bmover.move_account_data(set_avatar=set_avatar, gone_avatar=avatar, mapping=mapping)


if __name__ == "__main__":
    main()
