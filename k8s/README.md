# Elemta Kubernetes Deployment

## Architecture

This directory contains Kubernetes deployment files for the Elemta email platform. The deployment includes:

- **Elemta SMTP Server**: The main email server component
- **ClamAV**: For virus scanning (mocked in this deployment)
- **Rspamd**: For spam filtering

## Quick Start

### Prerequisites

- Kubernetes cluster (minikube, kind, or a cloud provider)
- `kubectl` configured to use your cluster
- Docker images built (run `make docker-build` in the project root)

### Deployment

To deploy Elemta to your Kubernetes cluster:

```bash
make k8s-deploy
```

This will create all necessary resources including:
- PersistentVolumeClaims for data storage
- ConfigMaps for configuration
- Deployment with the Elemta, ClamAV, and Rspamd containers
- Services to expose the components

### Testing

To test if the deployment is working correctly:

```bash
make k8s-test
```

This will run the test script located at `tests/k8s/test-elemta.sh` which tests the SMTP service, ClamAV, and Rspamd functionality.

## Management Commands

- **Deploy**: `make k8s-deploy`
- **Undeploy**: `make k8s-undeploy`
- **Stop**: `make k8s-down`
- **Start**: `make k8s-up`
- **Restart**: `make k8s-restart`
- **View Logs**: `make k8s-logs`
- **Check Status**: `make k8s-status`
- **Run Tests**: `make k8s-test`

## Configuration

### Elemta Configuration

The Elemta server is configured via the `elemta-config` ConfigMap in the `elemta-all.yaml` file. Key settings include:

- SMTP server settings
- ClamAV integration
- Rspamd integration

For production, you should modify:
- `hostname`: Set to your actual mail server hostname
- `greeting`: Customize the SMTP greeting
- Authentication settings if needed

### Rspamd Configuration

Rspamd is configured via the `rspamd-config` ConfigMap. The configuration includes:

- Web interface settings (port 11334, exposed as NodePort 30334)
- Protocol interface settings (port 11333)
- No authentication for testing (add authentication for production)

### ClamAV Configuration

In this deployment, ClamAV is mocked using a simple Alpine container with netcat to simulate the ClamAV service. For production, replace this with a real ClamAV container.

## File Structure

- `elemta-all.yaml`: The main Kubernetes deployment file
- `README.md`: This documentation
- `../tests/k8s/`: Directory containing test scripts

## Exposed Services

- **SMTP**: NodePort 30025 (mapped to port 25 in the container)
- **Rspamd Web Interface**: NodePort 30334 (mapped to port 11334 in the container)
- **ClamAV**: ClusterIP only (internal access via elemta-clamav:3310)

## Test Results

Recent testing confirms:

- **SMTP Service (port 30025)**: ✅ Working
- **Rspamd Web Interface (port 30334)**: ✅ Working
- **ClamAV Service (internal only)**: ❓ Not directly accessible from outside (expected)

The deployment is functioning correctly with the SMTP server and Rspamd web interface accessible from outside the cluster.

## Troubleshooting

### Common Issues

1. **Pods not starting**: Check for resource constraints or image pull issues
   ```bash
   kubectl describe pod -l app=elemta
   ```

2. **Services not accessible**: Verify service and pod status
   ```bash
   kubectl get services
   kubectl get pods
   ```

3. **Configuration issues**: Check logs for configuration errors
   ```bash
   kubectl logs -l app=elemta -c elemta
   kubectl logs -l app=elemta -c rspamd
   kubectl logs -l app=elemta -c clamav
   ``` 