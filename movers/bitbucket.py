import json
import logging
import base64
import requests
from .base_mover import BaseMover

logger = logging.getLogger('User move')
logger.setLevel(logging.DEBUG)

def _project_url(slug):
    return f'projects/{slug}'

def _user_url(session):
    return f'users/{session.auth.user}'

def _repo_url(prefix, repo):
    return f'{prefix}/repos/{repo}'

def _repo_restriction_project_url(slug, repo):
    return f'rest/branch-permissions/2.0/{_repo_url(_project_url(slug), repo)}/restrictions'

def _repo_restriction_user_url(session, repo):
    return _repo_restriction_project_url(f'~{session.auth.user}', repo)


REST_API_ENDPOINT='rest/api/1.0'
DENY_ALL_ACCESS_RESTRICTION=json.dumps({
    "type": "read-only",
    "matcher": {
        "id":"*",
        "type": {"id": "PATTERN", "name": "Pattern"},
        "active":True}
    })

class BitbucketMover(BaseMover):
    def __init__(self, creds, url):
        super().__init__(creds, url, REST_API_ENDPOINT)

    @staticmethod
    def test_connection(url):
        try:
            resp = requests.get(f'{url}/{REST_API_ENDPOINT}/application-properties')
        except Exception as exc:
            logger.error('Caught exception while connecting: %s', str(exc))
            return False

        if resp.status_code in range(200, 300) and 'displayName' in resp.json():
            j = resp.json()
            logger.info('Connected to %s/%s @ %s', j["displayName"], j["version"], url)
            return True
        else:
            logger.error('Connection to %s failed: %d.', url, resp.status_code)
            return False

    @staticmethod
    def test_login(url, account):
        resp = {}
        full = f'{url}/{REST_API_ENDPOINT}/users/{account.user}'
        try:
            resp = requests.get(full,
                    auth=(account.user, account.password),
                    headers = {'content-type': 'application/json'})
            logger.debug('Testing login for user %s at %s status %d',
                    account.user, full, resp.status_code)
            logger.debug(str(resp.json()))
        except Exception as exc:
            logger.error('Caught exception while connecting: %s', exc)
            return False


        return resp.status_code == 200 \
                and 'name' in resp.json() \
                and resp.json()['name'].lower() == account.user.lower()


    def get_private_repos(self, session=None):
        session = self.old if not session else session

        resp = session.get(f'users/{session.auth.user}/repos/')

        return [rjson['slug'] for rjson in resp.json()['values']] \
                if resp.status_code in range(200, 300) else []

    def _set_repo_permissions(self,
            prefix,
            repo,
            user_or_group,
            mode,
            permission='REPO_ADMIN',
            session=None):
        session = self.old if not session else session

        resp = session.put(f'{_repo_url(prefix, repo)}/permissions/{mode}',
                params={'name': user_or_group, 'permission': permission})

        return resp.status_code in range(200, 300)

    def _get_repo_permissions(self, prefix, repo, mode, session=None):
        session = self.old if not session else session

        return session.get(f'{_repo_url(prefix, repo)}/permissions/{mode}')


    def set_repo_permissions(self,
            project,
            repo,
            user,
            mode="users",
            permission='REPO_ADMIN',
            session=None):
        return self._set_repo_permissions(
                _project_url(project),
                repo,
                user,
                mode,
                permission,
                session)

    def set_private_repo_permissions(self,
            repo,
            user,
            mode="users",
            permission='REPO_ADMIN',
            session=None):
        session = self.old if not session else session
        return self._set_repo_permissions(
                _user_url(session),
                repo,
                user,
                mode,
                permission,
                session)

    def get_repo_permissions(self, project, repo, mode="users", session=None):
        return self._get_repo_permissions(_project_url(project), repo, mode, session)

    def get_private_repo_permissions(self, repo, mode="users", session=None):
        session = self.old if not session else session
        return self._get_repo_permissions(_user_url(session), repo, mode, session)


    def _move_repo(self, source_repo, dest_project, session):
        resp = session.post(source_repo, data = json.dumps({
            "project" : {
                           "key": dest_project
             }
        }), headers = {'content-type': 'application/json'})

        return resp

    def move_user_repo(self, repo, from_user=None, to_user=None):
        from_user = self.old if not from_user else from_user
        to_user = self.new if not to_user else to_user

        resp = self._move_repo(
                _repo_url(_user_url(from_user), repo),
                f'~{to_user.auth.user}',
                to_user)

        if resp.status_code in range(200, 300):
            logger.warn(
                    'Repo "%s" moved, but settings not, you might want to compare manually',
                    repo)
            return True
        else:
            logger.error('Failed to move repo, status=%d', resp.status_code)
            return False

    def move_project_repo(self, repo, from_project, to_project, session=None):
        raise NotImplementedError("Not implemented.")

    def get_prs(self, session=None, params={'state': 'OPEN', 'role': 'REVIEWER'}):
        session = self.old if not session else session
        resp = session.get('dashboard/pull-requests', params=params)

        prs = []
        if resp.status_code in range(200, 300):
            prs = [
                    (
                        value['title'],
                        value['toRef']['repository']['project']['key'],
                        value['toRef']['repository']['slug'],
                        value['id'],
                        [reviewer['user']['name'] for reviewer in value['reviewers']],
                        value['version']
                    )
                for value in resp.json()['values']]

        return prs

    def set_reviewer(self, project, repo, pr_id, reviewers, version, session=None):
        session = self.new if not session else session

        full = f'{_repo_url(_project_url(project), repo)}/pull-requests/{pr_id}'

        return session.put(full, data=json.dumps({
                    'id': pr_id,
                    'version': version,
                    'reviewers': [ {'user': {'name': uid}} for uid in reviewers]
                }),
                headers = {'content-type': 'application/json'
            })


    def get_avatar_png(self, session=None):
        """
        returns png binary data
        """
        session = self.old if not session else session
        resp = session.get(f'{_user_url(session)}/avatar.png', rest_call=False)
        return resp.content if resp.status_code in range(200, 300) else bytes()

    def set_avatar_png(self, avatar, session=None):
        session = self.new if not session else session
        return session.post(f'{_user_url(session)}/avatar.png',
                files=dict(avatar=('avatar.png', avatar)),
                headers={
                    'X-Atlassian-Token': 'no-check'})


    def _move_avatar(self):
        avatar = self.get_avatar_png(session=self.old)
        if avatar:
            resp = self.set_avatar_png(avatar, session=self.new)
            if resp.status_code in range(200, 300):
                logger.info("Configured avatar for new account.")
                return True
            else:
                logger.error(
                        'Failed to configure avatar for new account, status = %d.',
                        resp.status_code)
                return False

    def _deny_all_changes(self, repo, session=None):
        session = self.old if not session else session

        return session.post(
                _repo_restriction_user_url(session, repo),
                rest_call=False,    # it's REST, but different endpoint...
                data=DENY_ALL_ACCESS_RESTRICTION,
                headers = {'content-type': 'application/json'})

    def _copy_restrictions(self, repo, from_user=None, to_user=None):
        from_user = self.old if not from_user else from_user
        to_user = self.new if not to_user else to_user
        #TODO
        logger.warn('Not yet implemented. Copy settings manually...')

    def _copy_permission_for_mode(self, repo, from_user, to_user, mode, mapping=None):
        user_names = []
        mapped = []

        perm_request = self.get_private_repo_permissions(repo, mode, from_user)
        permissions = {}
        if perm_request.status_code in range(200,300) and 'values' in perm_request.json():
            for value in perm_request.json()['values']:
                perm = value['permission']
                name = value[mode[:-1]]['name']

                if not value['permission'] in permissions:
                    permissions[perm] = []
                user_names.append(name)

                permissions[perm].append(name.lower())
                mapped_user = None
                if mapping:
                    if name in mapping:
                        mapped_user = mapping[name]
                    elif name.lower() in mapping:
                        mapped_user = mapping[name.lower()]
                    elif name.upper() in mapping:
                        mapped_user = mapping[name.upper()]

                    if mapped_user is not None:
                        permissions[perm].append(mapped_user.lower())
                        mapped.append(mapped_user)
        else:
            logger.error(
                    'Failed getting %s permissions for repo %s, status=%d',
                    mode[:-1],
                    repo,
                    perm_request.status_code)

        for permission, names in permissions.items():
            if self.set_private_repo_permissions(
                    repo,
                    names,
                    mode=mode,
                    permission=permission,
                    session=to_user):
                logger.info(
                        'repo %s: Set %s for %s.',
                        repo,
                        permission,
                        ", ".join(names))
            else:
                logger.error(
                        'repo %s: Failed setting %s for %s. Set manually.',
                        repo,
                        permission,
                        ", ".join(names))
        logger.info('Mapped %d user IDs and added them to the permission lists.', len(mapped))

        return user_names, mapped



    def copy_permissions(self, repo, from_user=None, to_user=None, mapping=None):
        from_user = self.old if not from_user else from_user
        to_user = self.new if not to_user else to_user

        _users, _mapped = self._copy_permission_for_mode(repo, from_user, to_user, 'users', mapping)
        _groups, _unsude = self._copy_permission_for_mode(repo, from_user, to_user, 'groups', None)



    def _move_all_private(self, mapping, exceptions=[]):
        repos = self.get_private_repos()

        for repo in repos:
            if repo in exceptions:
                logger.debug('%s is in exceptions list. Skipping.', repo)
                continue
            logger.info('-------------------')
            logger.info('PROCESSING: repo %s...', repo)
            if self.set_private_repo_permissions(
                    repo,
                    self.new.auth.user,
                    mode="users",
                    permission='REPO_READ',
                    session=self.old):
                logger.info('repo %s: Add %s as reader.', repo, self.new.auth.user)
            else:
                logger.error(
                        'repo %s: Failed adding %s as reader, needs read permission at least.',
                        repo,
                        self.new.auth.user)
                return

            if self.move_user_repo(repo):
                self.copy_permissions(repo, self.old, self.new, mapping)
                if self._deny_all_changes(repo, self.old).status_code in range(200, 300):
                    logger.info('repo %s: Locked down repo successfully.', repo)
                else:
                    logger.error('repo %s: Failed to lock repo.', repo)

    def _change_reviewers(self):
        prs = self.get_prs(session=self.old)
        old = self.old.auth.user.lower()
        new = self.new.auth.user.lower()
        for pr in prs:
            title, project, repo, pr_id, reviewers, version = pr
            logger.info('-------------------')
            logger.info('PROCESSING: PR #%d in %s/%s, "%s"...', pr_id, project, repo, title)
            logger.info('  Removing %s as reviewer from PR', old)
            reviewers.remove(old)

            if new not in reviewers:
                logger.info('  Adding %s as reviewer to PR', new)
                reviewers.append(new)
            else:
                logger.info('  %s is already reviewer of PR', new)

            logger.info('  Updating reviewers.')
            resp = self.set_reviewer(project, repo, pr_id, reviewers, version, session=self.new)
            if resp.status_code in range(200, 300):
                logger.info('  Done')
            else:
                logger.error('  Failed, status=%d', resp.status_code)

    def get_ssh_keys(self, session=None):
        session = self.old if not session else session

        resp = session.get('rest/ssh/1.0/keys', rest_call=False, params={'user': session.auth.user})

        if resp.status_code in range(200,300):
            keys = [value['text'] for value in resp.json()['values']]
            logger.info(
                    'Received %d SSH keys for user %s.',
                    len(keys),
                    session.auth.user)
        else:
            logger.error(
                    'Failed to retrieve SSH keys for user %s.',
                    session.auth.user)

        return keys

    def delete_all_ssh_keys(self, session=None):
        session = self.old if not session else session

        resp = session.delete(
                'rest/ssh/1.0/keys',
                rest_call=False,
                params={'user': session.auth.user})
        if resp.status_code in range(200, 300):
            logger.info('Deleted all SSH keys for user %s', session.auth.user)
            return True
        else:
            logger.error('Failed to delete SSH keys.')
            return False

    def set_ssk_keys(self, keys, session=None):
        session = self.new if not session else session

        for key in keys:
            resp = session.post(
                    'rest/ssh/1.0/keys',
                    rest_call=False,    # still REST, but different endpoint..
                    params={'user': session.auth.user},
                    data=json.dumps({'text': key}),
                    headers = {'content-type': 'application/json'})
            if resp.status_code in range(200, 300):
                logger.info(
                        'Added ssh key for %s: %s..%s.',
                        session.auth.user,
                        key[:20],
                        key[-20:])
            else:
                logger.error(
                        'Failed to add ssh key for %s: %s..%s.',
                        session.auth.user,
                        key[:20],
                        key[-20:])

    def _move_ssh_keys(self, from_user=None, to_user=None):
        from_user = self.old if not from_user else from_user
        to_user = self.new if not to_user else to_user

        keys = self.get_ssh_keys(session=from_user)
        if not keys:
            return

        if self.delete_all_ssh_keys(session=from_user):
            self.set_ssk_keys(keys, session=to_user)
        else:
            logger.error('SSH keys could not be deleted,'\
                    'same SSH keys can not be set for a different user.')

    def _reconfigure_avatars(self, set_avatar=True, gone_avatar=None):
        self._move_avatar()
        if set_avatar and gone_avatar:
            resp = self.set_avatar_png(gone_avatar, session=self.old)
            if resp.status_code in range(200, 300):
                logger.info("Configured deprecated avatar for old account.")
            else:
                logger.error(
                        'Failed to configure deprecated avatar for old account, status=%d.',
                        resp.status_code)


    def move_account_data(self, set_avatar=True, gone_avatar=None, mapping=None):
        self._reconfigure_avatars(set_avatar=set_avatar, gone_avatar=gone_avatar)
        self._move_all_private(mapping)
        self._change_reviewers()
        self._move_ssh_keys()
