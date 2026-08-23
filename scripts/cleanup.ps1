$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
docker compose -f compose.test.yml down -v --remove-orphans
docker compose --profile demo down -v --remove-orphans
$managed = docker ps -aq --filter 'label=com.identitymesh.managed=true'
if ($managed) { docker rm -f $managed }
$networks = docker network ls -q --filter 'label=com.identitymesh.managed=true'
if ($networks) { docker network rm $networks }
$volumes = docker volume ls -q --filter 'label=com.identitymesh.managed=true'
if ($volumes) { docker volume rm $volumes }
