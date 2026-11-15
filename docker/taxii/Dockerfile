# Lab-only TAXII 2.1 server: OASIS medallion, pinned to a commit (see ADR-002).
# medallion has had no release since 3.0.0 (2020); the last commit is from 2023.
FROM python:3.15-slim

ARG MEDALLION_COMMIT=39e76bf18be5371e9570de7e5f340c3937b69c0d

# medallion still imports pkg_resources, which newer setuptools no longer ships.
RUN pip install --no-cache-dir \
        "setuptools<81" \
        "medallion @ https://github.com/oasis-open/cti-taxii-server/archive/${MEDALLION_COMMIT}.tar.gz" \
    && useradd --system --no-create-home taxii

WORKDIR /opt/taxii
COPY config.json data.json entrypoint.py ./

USER taxii
EXPOSE 5000
ENTRYPOINT ["python", "/opt/taxii/entrypoint.py"]
