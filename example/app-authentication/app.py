import pam

p = pam.pam()

p.authenticate('crboy', '', service='app-dev')
print(f'crboy got {p.code} {p.reason}')

