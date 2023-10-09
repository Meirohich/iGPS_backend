FROM python:3.10
WORKDIR .
COPY requirements.txt .
RUN apt-get update && \
    apt-get install -y libgeos-dev && \
    pip install --upgrade pip && \
    pip install utils
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "app/app.py"]
EXPOSE 8000