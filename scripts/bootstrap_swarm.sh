#!/bin/sh
set -eu
: "${REGISTRY:?Set REGISTRY}"
: "${IMAGE_TAG:?Set IMAGE_TAG}"
docker service create --name course-bootstrap --restart-condition none \
  --network course_authnet \
  --secret source=course_bootstrap_admin_password,target=bootstrap_admin_password \
  --secret source=course_manager_client_secret,target=manager_client_secret \
  --secret source=course_demo_password,target=demo_password \
  --with-registry-auth "$REGISTRY/api:$IMAGE_TAG" python /app/bootstrap.py
echo 'Inspect: docker service logs course-bootstrap'
echo 'Check exit code: docker inspect $(docker service ps -q course-bootstrap) --format "{{.Status.ContainerStatus.ExitCode}}"'
echo 'Only after exit code 0: docker service rm course-bootstrap; docker service scale course_keycloak=2'
