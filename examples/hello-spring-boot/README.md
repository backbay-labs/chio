# hello-spring-boot

Minimal Spring Boot example using [`sdks/jvm/chio-spring-boot`](../../sdks/jvm/chio-spring-boot/).

## What It Demonstrates

- `GET /hello` and `POST /echo` behind the real Chio servlet filter
- deny without capability and allow with a trust-issued capability token
- request body remains readable by the controller after Chio hashing
- receipt ids are emitted on the response header path

## Files

```text
ARCHITECTURE.md
README.md
build.gradle.kts
settings.gradle.kts
src/main/kotlin/...
src/test/kotlin/...
openapi.yaml
policy.yaml
run.sh
smoke.sh
```

## Run

Start the app only:

```bash
./run.sh
```

Run the full end-to-end smoke flow:

```bash
./smoke.sh
```

Run route-level tests without a sidecar:

```bash
../../sdks/jvm/gradlew --no-daemon -p . test
```
