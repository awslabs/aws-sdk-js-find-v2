FROM amazonlinux:2023
RUN dnf install -y nodejs24 && dnf clean all
RUN npm i -g corepack
WORKDIR /app
CMD ["sh", "-c", "yarn && node scripts/generateBundles.ts"]
