# Run the OpenFGA CLI from its Docker image, so nothing needs installing on Windows.
# The policy/ folder is mounted as the working directory.
#
#   .\scripts\fga.ps1 model test --tests tests.fga.yaml
#   .\scripts\fga.ps1 model transform --file model.fga
#   .\scripts\fga.ps1 store list            # talks to the local OpenFGA on :8080
#
# Pinned to the version used by export_model_json.ps1 (and tested on Day 7).

$repo = Split-Path -Parent $PSScriptRoot
docker run --rm `
  -v "${repo}\policy:/policy" `
  -w /policy `
  -e FGA_API_URL=http://host.docker.internal:8080 `
  openfga/cli:v0.7.8 @args
exit $LASTEXITCODE
