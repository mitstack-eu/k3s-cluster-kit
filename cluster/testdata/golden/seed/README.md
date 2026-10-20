# Repository credentials

Each app slice commits three files here: its app's Argo CD repository Secret,
and the Role and RoleBinding that let the repository-token refresh patch that
Secret's token.

The Application in `cluster/repository-credentials.yaml` syncs this
directory. It applies only JSON and YAML files, so it never applies this
README, which keeps the directory in Git while no slice writes here.
