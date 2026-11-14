# Run the OpenFGA CLI from its Docker image, so nothing needs installing on Windows.
# The policy/ folder is mounted as the working directory.
#
#   .\scripts\fga.ps1 model test --tests tests.fga.yaml
#   .\scripts\fga.ps1 model transform --file model.fga
#   .\scripts\fga.ps1 store list            # talks to the local OpenFGA on :8080
#
# Pin the image (e.g. openfga/cli:v0.7.x) once you've confirmed a version that works.

$repo = Split-Path -Parent $PSScriptRoot
docker run --rm `
  -v "${repo}\policy:/policy" `
  -w /policy `
  -e FGA_API_URL=http://host.docker.internal:8080 `
  openfga/cli @args
exit $LASTEXITCODE
