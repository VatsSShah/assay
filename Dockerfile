# Assay experiment runner. Standard library only: nothing is installed beyond the checkout.
#
# The base image is referenced by TAG. Pin it by digest at release time, e.g.
#   FROM python:3.12-slim@sha256:<digest you verified>
# and pass the built image's own digest to runs as ASSAY_CONTAINER_IMAGE_DIGEST. Until then the
# experiment manifest records container_image_digest as null / unknown -- Assay never invents one.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/assay/src

WORKDIR /assay
COPY . /assay

# Run as an unprivileged user; experiment output goes to a mounted volume.
RUN useradd --create-home --uid 10001 assay \
    && mkdir -p /assay/experiments/runs \
    && chown -R assay:assay /assay/experiments/runs
USER assay

# Default: the offline synthetic example (no network, no key).
CMD ["python", "-m", "assay_bench", "experiment", "run", "--config", "experiments/examples/synthetic-local/experiment.json", "--out", "experiments/runs"]
