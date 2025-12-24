FROM amazonlinux:2023
RUN dnf install -y nodejs24
RUN npm i -g corepack
WORKDIR /app
CMD ["sh", "-c", "yarn && node scripts/generateBundles.ts"]
