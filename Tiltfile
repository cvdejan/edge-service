# Build
custom_build(
    # Name of the container image
    ref = 'ghcr.io/cvdejan/edge-service',
    # Command to build the container image
    command = './mvnw spring-boot:build-image -Dspring-boot.build-image.imageName=$EXPECTED_REF -Dmaven.test.skip=true',
    # Files to watch that trigger a new build
    deps = ['pom.xml', 'src']
)

# Deploy
#k8s_yaml(['k8s/deployment.yml', 'k8s/service.yml'])
k8s_yaml(kustomize('k8s'))

# Manage
k8s_resource('edge-service', port_forwards=['9000'])