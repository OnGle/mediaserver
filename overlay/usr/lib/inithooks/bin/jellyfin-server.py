#!/usr/bin/python3
# Copyright (c) 2015 Jonathan Struebel <jonathan.struebel@gmail.com>
# Modified for Jellyfin 2019 TurnKey GNU/Linux <jeremy@turnkeylinux.org>
"""Configure Jellyfin Media Server

Arguments:
    none

Options:
    -p --pass=    if not provided, will ask interactively
"""

import sys
import getopt
import subprocess
from subprocess import PIPE
import signal
import json
import hashlib
import os
import base64
import sqlite3
import uuid

# Taken from /var/lib/jellyfin/jellyfin.db table=Permissions
default_admin_permissions = [
    # id, kind, value, row version
    [1, 0, 1, 1],
    [2, 18, 1, 1],
    [3, 20, 0, 1],
    [4, 9, 1, 1],
    [5, 3, 1, 1],
    [6, 6, 1, 1],
    [7, 8, 1, 1],
    [8, 12, 1, 1],
    [9, 4, 1, 1],
    [10, 17, 1, 1],
    [11, 5, 1, 1],
    [12, 7, 1, 1],
    [13, 13, 1, 1],
    [14, 11, 1, 1],
    [15, 10, 1, 1],
    [16, 16, 1, 1],
    [17, 14, 1, 1],
    [18, 15, 1, 1],
    [19, 1, 1, 1],
    [20, 2, 0, 1],
    [21, 19, 1, 1]
]

# Taken from /var/lib/jellyfin/jellyfin.db table=Preferences
default_admin_preferences = [
    # id, kind, value, row version
    [1, 9, None, 1], 
    [2, 8, None, 1], 
    [3, 7, None, 1], 
    [4, 6, None, 1], 
    [5, 5, None, 1], 
    [6, 0, None, 1], 
    [7, 3, None, 1], 
    [8, 2, None, 1], 
    [9, 1, None, 1], 
    [10, 10, None, 1],
    [11, 4, None, 1],
    [12, 11, None, 1]
]

def fatal(s):
    print("Error:", s, file=sys.stderr)
    sys.exit(1)

def usage(s=None):
    if s:
        print("Error:", s, file=sys.stderr)
    print("Syntax: %s [options]" % sys.argv[0], file=sys.stderr)
    print(__doc__, file=sys.stderr)
    sys.exit(1)

def hashpass(passwd):
    salt = os.urandom(32)
    iterations = 1000
    pw_hash = base64.b16encode(hashlib.pbkdf2_hmac('sha512', passwd, salt, iterations))
    return f'$PBKDF2$iterations={iterations}${pw_hash.decode()}${base64.b16encode(salt).decode()}'

def main():
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "hp:", ['help', 'pass='])
    except getopt.GetoptError as e:
        usage(e)

    password = ""
    for opt, val in opts:
        if opt in ('-h', '--help'):
            usage()
        elif opt in ('-p', '--pass'):
            password = val

    if not password:
        from dialog_wrapper import Dialog
        d = Dialog('TurnKey GNU/Linux - First boot configuration')
        password = d.get_password(
            "Jellyfin User Password",
            "Please enter new password for the Jellyfin Server jellyfin account.")

    admin_user = 'jellyfin'

    conn = sqlite3.connect('/var/lib/jellyfin/data/jellyfin.db')

    c = conn.cursor()
    c.execute('SELECT * FROM Users where Username=?', (admin_user,))
    row = c.fetchone()
    if row is None:
        uid = str(uuid.uuid4()).upper()
        row = {
            'Id': uid,
            'Username': admin_user,
            'Password': hashpass(password.encode('utf8')),
            'EasyPassword': None,
            'MustUpdatePassword': 0,
            'AudioLanguagePreference': None,
            'AuthenticationProviderId':
                'Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider',
            'PasswordResetProviderId':
                'Jellyfin.Server.Implementations.Users.DefaultPasswordResetProvider',
            'InvalidLoginAttemptCount': 0,
            'LastActivityDate': None,
            'LastLoginDate': None,
            'LoginAttemptsBeforeLockout': None,
            'SubtitleMode': 0,
            'PlayDefaultAudioTrack': 1,
            'SubtitleLanguagePreference': None,
            'DisplayMissingEpisodes': 0,
            'DisplayCollectionsView': 0,
            'EnableLocalPassword': 0,
            'HidePlayedInLatest': 1,
            'RememberAudioSelections': 1,
            'RememberSubtitleSelections': 1,
            'EnableNextEpisodeAutoPlay': 1,
            'EnableAutoLogin': 0,
            'EnableeUserPreferenceAccess': 1,
            'MaxParentalAgeRating': None,
            'RemoteClientBitrateLimit': None,
            'InternalId': 1,
            'SyncPlayAccess': 0,
            'RowVersion': 1
        }
        c.execute('''
            insert into Users values (
                :Id,
                :Username,
                :Password,
                :EasyPassword,
                :MustUpdatePassword,
                :AudioLanguagePreference,
                :AuthenticationProviderId,
                :PasswordResetProviderId,
                :InvalidLoginAttemptCount,
                :LastActivityDate,
                :LastLoginDate,
                :LoginAttemptsBeforeLockout,
                :SubtitleMode,
                :PlayDefaultAudioTrack,
                :SubtitleLanguagePreference,
                :DisplayMissingEpisodes,
                :DisplayCollectionsView,
                :EnableLocalPassword,
                :HidePlayedInLatest,
                :RememberAudioSelections,
                :RememberSubtitleSelections,
                :EnableNextEpisodeAutoPlay,
                :EnableAutoLogin,
                :EnableeUserPreferenceAccess,
                :MaxParentalAgeRating,
                :RemoteClientBitrateLimit,
                :InternalId,
                :SyncPlayAccess,
                :RowVersion
            )
        ''', row)
        # id, kind, value, row version
        permissions = [ [*row, uid] for row in default_admin_permissions ]
        c.execute('insert into Permissions (?, ?, ?, ?)', permissions)
        preferences = [ [*row, uid] for row in default_admin_preferences ]
        c.execute('insert into Preferences (?, ?, ?, ?)', preferences)

    else:
        c.execute('update Users set Password=:password where Username=:username',
                { 'password': hashpass(password.encode('utf8')), 'username': admin_user })
    conn.commit()
    c.close()
    conn.close()

if __name__ == "__main__":
    main()

