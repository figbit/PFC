#!/bin/bash

# KPMG-PFCG Pentest Finding Card Generator - Deployment Script
# This script builds and runs the Docker container

echo "🛡️ KPMG-PFCG Pentest Finding Card Generator - Docker Deployment"
echo "=============================================================="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Stop any existing containers
echo "🛑 Stopping existing containers..."
docker-compose down

# Build the Docker image
echo "🔨 Building Docker image..."
docker-compose build --no-cache

# Start the container
echo "🚀 Starting KPMG-PFCG container..."
docker-compose up -d

# Wait for container to be ready
echo "⏳ Waiting for container to be ready..."
sleep 10

# Check if container is running
if [ "$(docker-compose ps -q)" ]; then
    echo "✅ KPMG-PFCG Pentest Finding Card Generator is now running!"
    echo "🌐 Access the application at: http://localhost:1881"
    echo ""
    echo "📋 Useful commands:"
    echo "   View logs:     docker-compose logs -f"
    echo "   Stop service:  docker-compose down"
    echo "   Restart:       docker-compose restart"
    echo ""
else
    echo "❌ Failed to start container. Check logs with: docker-compose logs"
    exit 1
fi 