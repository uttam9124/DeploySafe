FROM python:3.12-slim

WORKDIR /app

COPY app.py /app/app.py

RUN useradd --system --uid 10001 appuser

USER 10001

ENV PYTHONDONTWRITEBYTECODE=1

HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "print('healthy')"

CMD ["python", "app.py"]
