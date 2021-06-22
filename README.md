Atlassian/Bitbucket Account Move
================================


> :warning: **WARNING: This is more a brain dump than a tested and usable tool!**
> 
> There are no backup, recovery or any kind of other safety mechanisms.
> Handle with care!



In order to move from one Atlassian account to another one (one user ID to the
next) on the same server instance, I started a python script to automate this
task.
Never got the time to finish or continue it and I'm not planning to.
Even though this is an ... unconventional thing to do in the first place it
might be helpful for someone else one day.


The code is far from perfect and if I'd have to do it again or even finish it,
I'd rather use something like the
[atlassian-python-api](https://github.com/atlassian-api/atlassian-python-api)
than writing the API interaction from scratch (but, where would be the fun in
that? ;-P )
Still, it served my purpose, and successfully moved my data.


_Supports_:
- Bitbucket (only!)
  - Moving private repos (by fork) from old to new account
    - *ONLY* Repository Permissions are copied, nothing else!

      You probably want to *manually* copy Branch Permissions and other things.
    - Fixes other people's account IDs, if they have moved as well based on
      an csv table (first column: old ID, second: new ID; separator ",")
  - Changing assigned reviewer in PRs from old to new account
  - Setting the avatar from old to new account
  - Optionally Setting the avatar for the old account to some 'Deprectated
    account' avatar
  - Setting a 'deprecated account' avatar for the old account
  - Copying over SSH pub-keys from old to new account




# Usage

Make sure you've read and understood the disclaimer above!
If you still want to use it:

```
% ./move_atlassian_account.py
--------------------------------------------------------------------------------
Specify Bitbucket URL: https://example.com/bitbucket
INFO       Connected to Bitbucket/7.1.1 @ https://example.com/bitbucket
--------------------------------------------------------------------------------
Old Account credentials
	user name: MYFIRSTUSER
	password: 
INFO       Got working credentials for Old Account
INFO       Account MYFIRSTUSER configured.
--------------------------------------------------------------------------------
New Account credentials
	user name: MYSECONDUSER
	password: 
INFO       Got working credentials for New Account
INFO       Account MYSECONDUSER configured.
Use mapping file (csv, first column: old ID, second: new ID)? [Y|n] 
Mapping path: my_user_mapping.csv
INFO       Using mapping from my_user_mapping.csv
Use "deprecated account" avatar file (png only!)? [Y|n] 
Avatar path: my_avatar.png
INFO       Using Avatar from my_avatar.png
--------------------------------------------------------------------------------
End of interactive part. Hit return to continue (CTRL+C to cancel): 
--------------------------------------------------------------------------------
```

Followed by lots of log outputs....




