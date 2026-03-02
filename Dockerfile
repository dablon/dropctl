FROM rust:1.75-bookworm

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source
COPY . .

# Build dependencies
RUN cargo fetch

# Default command
CMD ["cargo", "test", "--lib"]
