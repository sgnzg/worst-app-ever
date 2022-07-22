FROM python:latest
COPY app/ /app/
COPY secrets /secrets
RUN pip3 install -r /app/requirements.txt
WORKDIR /app/
CMD uvicorn main:app --host 0.0.0.0