# Suricata Rule Browser - Docker Deployment

This directory contains Docker configuration files for running the Suricata Rule Browser in a containerized environment.

## Quick Start

### Using Docker Compose (Recommended)

1. **Navigate to the docker directory:**
   ```bash
   cd docker
   ```

2. **Start the application:**
   ```bash
   docker-compose up -d
   ```

3. **Access the application:**
   - Web Interface: http://localhost:8000
   - API Documentation: http://localhost:8000/docs
   - Health Check: http://localhost:8000/health

4. **View logs:**
   ```bash
   docker-compose logs -f
   ```

5. **Stop the application:**
   ```bash
   docker-compose down
   ```

### Using Docker CLI

1. **Build the image:**
   ```bash
   docker build -t suricata-rule-browser -f docker/Dockerfile .
   ```

2. **Run the container:**
   ```bash
   docker run -d \
     --name suricata-rule-browser \
     -p 8000:8000 \
     -v $(pwd)/data:/app/data \
     -v $(pwd)/rules.yaml:/app/rules.yaml:ro \
     suricata-rule-browser
   ```

3. **Stop and remove the container:**
   ```bash
   docker stop suricata-rule-browser
   docker rm suricata-rule-browser
   ```

## Configuration

### Volume Mappings

The docker-compose.yml file includes the following volume mappings:

- **`../data:/app/data`** - Persistent storage for downloaded rules and rule databases
- **`../rules.yaml:/app/rules.yaml:ro`** - Rules source configuration (read-only)

### Environment Variables

You can customize the following environment variables in docker-compose.yml:

- **`TZ`** - Timezone setting (default: UTC)

### Port Configuration

By default, the application runs on port 8000. To change this, modify the port mapping in docker-compose.yml:

```yaml
ports:
  - "8080:8000"  # Maps host port 8080 to container port 8000
```

### Resource Limits

The docker-compose.yml includes resource limits to prevent excessive resource usage:

- **CPU Limit:** 2 CPUs
- **Memory Limit:** 1GB
- **CPU Reservation:** 0.5 CPUs
- **Memory Reservation:** 256MB

Adjust these values based on your needs and available resources.

## Custom Rules

### Adding Local Custom Rules

1. Create a custom rules directory:
   ```bash
   mkdir -p custom-rules
   ```

2. Place your .rules files in this directory

3. Uncomment the custom rules volume in docker-compose.yml:
   ```yaml
   volumes:
     - ./custom-rules:/app/custom-rules:ro
   ```

4. Update rules.yaml to include your custom rules:
   ```yaml
   sources:
     - name: custom
       type: directory
       description: Custom local rules
       path: /app/custom-rules
       enabled: true
   ```

5. Restart the container:
   ```bash
   docker-compose restart
   ```

## Troubleshooting

### Container Health Check

Check the container health status:
```bash
docker ps
```

The STATUS column should show "healthy" after the startup period.

### View Application Logs

```bash
docker-compose logs -f suricata-rule-browser
```

### Access Container Shell

```bash
docker-compose exec suricata-rule-browser /bin/bash
```

### Rules Not Loading

1. Verify the data directory permissions:
   ```bash
   ls -la ../data
   ```

2. Check if rules.yaml is properly mounted:
   ```bash
   docker-compose exec suricata-rule-browser cat /app/rules.yaml
   ```

3. Verify downloaded rules:
   ```bash
   docker-compose exec suricata-rule-browser ls -la /app/data/rules/
   ```

### Rebuild the Image

If you've made changes to the application code:

```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## Data Persistence

The `data` directory is mounted as a volume, which means:

- Downloaded rules are persisted between container restarts
- The download cache is maintained
- Rules are only re-downloaded when the cache expires (based on `cache_hours` in rules.yaml)

To force re-download of all rules:

```bash
# Remove the data directory contents
rm -rf ../data/rules/*

# Restart the container
docker-compose restart
```

## Security Considerations

1. **Read-only Configuration:** The rules.yaml file is mounted as read-only to prevent accidental modification
2. **Network Isolation:** The container runs in its own network namespace
3. **Non-root User:** Consider running as a non-root user in production (see Dockerfile modifications below)
4. **Firewall:** Only expose port 8000 to trusted networks

### Running as Non-root User (Production)

For production deployments, modify the Dockerfile to run as a non-root user:

```dockerfile
# Add before CMD instruction
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser
```

## Updating

To update to the latest version:

```bash
cd docker
docker-compose down
docker-compose pull
docker-compose build --no-cache
docker-compose up -d
```

## Support

For issues and questions:
- Check the main README.md in the project root
- Review the application logs
- Verify your rules.yaml configuration
- Ensure proper file permissions on mounted volumes
