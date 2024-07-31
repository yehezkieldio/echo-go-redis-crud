# Bun version: 1.1.20
# Node.js version: 20.12.2

# Install dependencies
FROM imbios/bun-node:1.1.20-20.12.2-slim AS deps

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get -y update && \
  apt-get install -yq openssl git ca-certificates tzdata && \
  ln -fs /usr/share/zoneinfo/Asia/Makassar /etc/localtime && \
  dpkg-reconfigure -f noninteractive tzdata
WORKDIR /app

COPY package.json bun.lockb tsconfig.json ./
RUN bun install

# Build the project
FROM deps AS builder

WORKDIR /app

COPY . .

# Run the project
FROM imbios/bun-node:1.1.20-20.12.2-slim AS runner

WORKDIR /app

# COPY --from=builder /app/docker/wait-for-it.sh /usr/local/bin/wait-for-it.sh
# RUN chmod +x /usr/local/bin/wait-for-it.sh

COPY --from=deps /app/node_modules node_modules
COPY --from=builder /app/.env.prod .env.prod

ENV NODE_ENV=production

COPY --from=builder /app/package.json .
COPY --from=builder /app/tsconfig.json .
COPY --from=builder /app/drizzle.config.ts .
COPY --from=builder /app/src src

# CMD ["wait-for-it.sh", "imperia_pg_prod:5432", "--", "sh", "-c", "bun run db:push && bun run start"]

CMD ["bun", "run", "start"]