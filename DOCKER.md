# 🐳 Docker Quick Start Guide

## Prerequisites
- Docker installed ([Get Docker](https://docs.docker.com/get-docker/))
- Docker Compose installed (usually comes with Docker Desktop)

## Method 1: Docker Build & Run (Simple)

```bash
# 1. Build the Docker image
docker build -t cybernet-sentinel:latest .

# 2. Run the container
docker run -it --rm \
  --network host \
  --privileged \
  --name sentinel \
  cybernet-sentinel:latest

# That's it! The network analyzer will start.
```

## Method 2: Docker Compose (Recommended)

```bash
# 1. Start the service
docker-compose up -d

# 2. View logs
docker-compose logs -f sentinel

# 3. Access the container
docker-compose exec sentinel bash

# 4. Stop the service
docker-compose down
```

## Method 3: With Custom Configuration

```bash
# 1. Create environment file
cp .env.example .env

# 2. Edit .env with your settings
nano .env

# 3. Run with environment variables
docker run -it --rm \
  --network host \
  --privileged \
  --env-file .env \
  -v $(pwd)/reports:/app/reports \
  cybernet-sentinel:latest
```

## Common Docker Commands

### Build
```bash
# Build image
docker build -t cybernet-sentinel:latest .

# Build without cache (fresh build)
docker build --no-cache -t cybernet-sentinel:latest .

# Build with custom tag
docker build -t cybernet-sentinel:v2.0 .
```

### Run
```bash
# Interactive mode
docker run -it --rm --network host --privileged cybernet-sentinel

# Background mode (detached)
docker run -d --network host --privileged --name sentinel cybernet-sentinel

# With volume mounts
docker run -it --rm \
  --network host \
  --privileged \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/logs:/app/logs \
  cybernet-sentinel
```

### Manage
```bash
# List running containers
docker ps

# Stop container
docker stop sentinel

# Remove container
docker rm sentinel

# View logs
docker logs sentinel
docker logs -f sentinel  # Follow logs

# Access container shell
docker exec -it sentinel bash
```

### Cleanup
```bash
# Remove container
docker rm -f sentinel

# Remove image
docker rmi cybernet-sentinel:latest

# Remove all unused images
docker image prune -a

# Clean everything
docker system prune -a
```

## Docker Compose Commands

### Basic Operations
```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# Restart services
docker-compose restart

# View logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f sentinel
```

### Advanced Operations
```bash
# Start with database
docker-compose --profile with-db up -d

# Start with web dashboard
docker-compose --profile with-web up -d

# Start everything
docker-compose --profile with-db --profile with-web up -d

# Rebuild services
docker-compose build --no-cache
docker-compose up -d

# Scale services
docker-compose up -d --scale sentinel=3

# Remove volumes
docker-compose down -v
```

## Troubleshooting

### Issue: Permission Denied
**Solution:** Ensure you're running with `--privileged` flag
```bash
docker run -it --rm --network host --privileged cybernet-sentinel
```

### Issue: Network Interface Not Found
**Solution:** Use `--network host` to access host network
```bash
docker run -it --rm --network host --privileged cybernet-sentinel
```

### Issue: Cannot Capture Packets
**Solution:** 
1. Install Npcap on Windows host
2. Run container with privileged mode
3. Verify network mode is set to `host`

### Issue: Container Won't Start
**Solution:** Check logs
```bash
docker logs sentinel
```

### Issue: Out of Disk Space
**Solution:** Clean up Docker resources
```bash
docker system prune -a -f
docker volume prune -f
```

## Production Deployment

### Using Docker Compose (Production)

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  sentinel:
    image: cybernet-sentinel:latest
    restart: always
    network_mode: host
    privileged: true
    volumes:
      - /opt/sentinel/reports:/app/reports
      - /opt/sentinel/logs:/app/logs
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "5"
```

```bash
# Deploy
docker-compose -f docker-compose.prod.yml up -d

# Update
docker-compose -f docker-compose.prod.yml pull
docker-compose -f docker-compose.prod.yml up -d
```

### Using Docker Swarm

```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.yml sentinel

# List services
docker stack services sentinel

# View logs
docker service logs -f sentinel_sentinel

# Remove stack
docker stack rm sentinel
```

## Performance Tuning

### Resource Limits
```bash
# Limit CPU and memory
docker run -it --rm \
  --network host \
  --privileged \
  --cpus="2.0" \
  --memory="2g" \
  cybernet-sentinel
```

### Volume Performance
```bash
# Use named volumes for better performance
docker volume create sentinel-reports
docker run -it --rm \
  --network host \
  --privileged \
  -v sentinel-reports:/app/reports \
  cybernet-sentinel
```

## Security Best Practices

1. **Don't run as root in production**
   - Container already uses non-root user by default
   
2. **Use specific image tags**
   ```bash
   docker build -t cybernet-sentinel:2.0.0 .
   ```

3. **Scan for vulnerabilities**
   ```bash
   docker scan cybernet-sentinel:latest
   ```

4. **Use secrets for sensitive data**
   ```bash
   docker secret create db_password /path/to/password.txt
   ```

5. **Keep images updated**
   ```bash
   docker-compose pull
   docker-compose up -d
   ```

## References

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [Dockerfile Best Practices](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
